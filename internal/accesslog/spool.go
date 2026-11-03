package accesslog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Cursor struct {
	Path        string `json:"path"`
	FileID      string `json:"fileId"`
	Generation  string `json:"generation"`
	Offset      int64  `json:"offset"`
	PrefixBytes int    `json:"prefixBytes"`
	PrefixHash  string `json:"prefixHash"`
	AnchorBytes int    `json:"anchorBytes"`
	AnchorHash  string `json:"anchorHash"`
	Skipping    bool   `json:"skipping"`
}

type Statistics struct {
	Expired   int64 `json:"expired"`
	Overflow  int64 `json:"overflow"`
	Malformed int64 `json:"malformed"`
	Oversized int64 `json:"oversized"`
}

type State struct {
	Cursor        Cursor     `json:"cursor"`
	Sequence      int64      `json:"sequence"`
	Failures      int        `json:"failures"`
	NextAttemptAt int64      `json:"nextAttemptAt"`
	Statistics    Statistics `json:"statistics"`
}

type diskBatch struct {
	Batch  Batch  `json:"batch"`
	Cursor Cursor `json:"cursor"`
}

type queuedFile struct {
	name          string
	size, created int64
	count         int
}

// Spool stores bounded immutable batch files. File contents, the current state
// and atomic-write temporary files all count toward the disk budget. Payloads
// are loaded one batch at a time; the bounded index contains metadata only.
type Spool struct {
	mu                           sync.Mutex
	dir                          string
	state                        State
	stateBytes, bytes, diskLimit int64
	files                        []queuedFile
	Wake                         chan struct{}
}

const maxDiskEntry = MaxBatchBytes + 4096
const maxStateBytes = 8192
const maxIndexEntries = (MaxMemoryBytes - 8*maxDiskEntry) / 256

func OpenSpool(dir string, now time.Time) (*Spool, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, diskLimit: MaxDiskBytes, Wake: make(chan struct{}, 1)}
	var data []byte
	f, err := os.Open(filepath.Join(dir, "state.json"))
	if err == nil {
		data, err = io.ReadAll(io.LimitReader(f, maxStateBytes+1))
		_ = f.Close()
	}
	if err == nil {
		if len(data) > maxStateBytes || json.Unmarshal(data, &s.state) != nil {
			return nil, errors.New("invalid_access_log_state")
		}
		s.stateBytes = int64(len(data))
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	for {
		entries, err := directory.ReadDir(128)
		if err != nil && err != io.EOF {
			return nil, err
		}
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasPrefix(name, ".accesslog-") {
				if err := os.Remove(filepath.Join(dir, name)); err != nil {
					return nil, err
				}
				continue
			}
			if !strings.HasSuffix(name, ".batch") || !entry.Type().IsRegular() {
				continue
			}
			parts := strings.Split(strings.TrimSuffix(name, ".batch"), "-")
			if len(parts) != 3 {
				return nil, errors.New("invalid_access_log_queue_name")
			}
			sequence, e1 := strconv.ParseInt(parts[0], 10, 64)
			created, e2 := strconv.ParseInt(parts[1], 10, 64)
			count, e3 := strconv.Atoi(parts[2])
			if e1 != nil || e2 != nil || e3 != nil || count < 1 || count > MaxRecords {
				return nil, errors.New("invalid_access_log_queue_name")
			}
			s.state.Sequence = max(sequence, s.state.Sequence)
			if created < now.Add(-OfflineRetention).UnixMilli() {
				if err := os.Remove(filepath.Join(dir, name)); err != nil {
					return nil, err
				}
				s.state.Statistics.Expired += int64(count)
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return nil, err
			}
			if info.Size() > maxDiskEntry {
				return nil, errors.New("oversized_access_log_queue_file")
			}
			s.files = append(s.files, queuedFile{name: name, size: info.Size(), created: created, count: count})
			s.bytes += info.Size()
			if len(s.files) > maxIndexEntries { // Bound even a directory left by an older process.
				sort.Slice(s.files, func(i, j int) bool { return s.files[i].name < s.files[j].name })
				if err := s.dropOldest(false); err != nil {
					return nil, err
				}
			}
		}
		if err == io.EOF {
			break
		}
	}
	sort.Slice(s.files, func(i, j int) bool { return s.files[i].name < s.files[j].name })
	if err := s.makeRoom(maxStateBytes); err != nil {
		return nil, err
	}
	if err := s.save(s.state); err != nil {
		return nil, err
	}
	return s, nil
}

func atomicWrite(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".accesslog-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		d, e := os.Open(dir)
		if e != nil {
			return e
		}
		err = d.Sync()
		_ = d.Close()
		return err
	}
	return nil
}

func (s *Spool) save(state State) error {
	if err := s.makeRoom(maxStateBytes); err != nil {
		return err
	}
	state.Statistics.Expired = s.state.Statistics.Expired
	state.Statistics.Overflow = s.state.Statistics.Overflow
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data) > maxStateBytes {
		return errors.New("access_log_state_too_large")
	}
	if err := atomicWrite(s.dir, "state.json", data); err != nil {
		if info, e := os.Stat(filepath.Join(s.dir, "state.json")); e == nil {
			s.stateBytes = info.Size()
		}
		return err
	}
	s.state = state
	s.stateBytes = int64(len(data))
	return nil
}

func (s *Spool) dropOldest(expired bool) error {
	file := s.files[0]
	if err := os.Remove(filepath.Join(s.dir, file.name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	s.bytes -= file.size
	s.files[0] = queuedFile{}
	s.files = s.files[1:]
	if expired {
		s.state.Statistics.Expired += int64(file.count)
	} else {
		s.state.Statistics.Overflow += int64(file.count)
	}
	return nil
}

func (s *Spool) makeRoom(needed int64) error {
	for len(s.files) > 0 && (s.bytes+s.stateBytes+needed > s.diskLimit || len(s.files) >= maxIndexEntries) {
		if err := s.dropOldest(false); err != nil {
			return err
		}
	}
	if s.bytes+s.stateBytes+needed > s.diskLimit {
		return errors.New("access_log_disk_budget_too_small")
	}
	return nil
}

func (s *Spool) Snapshot() State { s.mu.Lock(); defer s.mu.Unlock(); return s.state }

func (s *Spool) Commit(records []Record, cursor Cursor, stats Statistics, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.prune(now); err != nil {
		return err
	}
	if len(records) > 0 {
		batch := Batch{ID: uuid.NewString(), CreatedAt: now.UnixMilli(), Records: records}
		body, err := json.Marshal(batch)
		if err != nil {
			return err
		}
		if len(body) > MaxBatchBytes || batch.Validate() != nil {
			return ErrInvalidBatch
		}
		data, err := json.Marshal(diskBatch{Batch: batch, Cursor: cursor})
		if err != nil {
			return err
		}
		if len(data) > maxDiskEntry {
			return ErrInvalidBatch
		}
		if err := s.makeRoom(int64(len(data)) + maxStateBytes); err != nil {
			return err
		}
		s.state.Sequence++ // Never reuse a filename if the later cursor write fails.
		name := fmt.Sprintf("%020d-%020d-%03d.batch", s.state.Sequence, now.UnixMilli(), len(records))
		writeErr := atomicWrite(s.dir, name, data)
		// A directory fsync can fail after rename has published the file. Keep
		// that file in the bounded index even while the cursor remains behind.
		if writeErr == nil {
			s.files = append(s.files, queuedFile{name: name, size: int64(len(data)), created: now.UnixMilli(), count: len(records)})
			s.bytes += int64(len(data))
		} else {
			if info, e := os.Stat(filepath.Join(s.dir, name)); e == nil {
				s.files = append(s.files, queuedFile{name: name, size: info.Size(), created: now.UnixMilli(), count: len(records)})
				s.bytes += info.Size()
			}
			return writeErr
		}
	}
	state := s.state
	state.Cursor = cursor
	state.Statistics.Malformed += stats.Malformed
	state.Statistics.Oversized += stats.Oversized
	if err := s.makeRoom(maxStateBytes); err != nil {
		return err
	}
	// makeRoom may have updated eviction counters.
	state.Statistics.Expired = s.state.Statistics.Expired
	state.Statistics.Overflow = s.state.Statistics.Overflow
	if err := s.save(state); err != nil {
		return err
	}
	if len(records) > 0 {
		select {
		case s.Wake <- struct{}{}:
		default:
		}
	}
	return nil
}

func (s *Spool) prune(now time.Time) error {
	// The sequence orders arrival. Wall-clock regressions must not hide expired files.
	for i := 0; i < len(s.files); {
		if s.files[i].created >= now.Add(-OfflineRetention).UnixMilli() {
			i++
			continue
		}
		file := s.files[i]
		if err := os.Remove(filepath.Join(s.dir, file.name)); err != nil && !os.IsNotExist(err) {
			return err
		}
		s.bytes -= file.size
		s.state.Statistics.Expired += int64(file.count)
		s.files = append(s.files[:i], s.files[i+1:]...)
	}
	return nil
}

func (s *Spool) Next(now time.Time) (string, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.prune(now); err != nil {
		return "", nil, err
	}
	if len(s.files) == 0 {
		return "", nil, nil
	}
	file := s.files[0]
	f, err := os.Open(filepath.Join(s.dir, file.name))
	if err != nil {
		return "", nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxDiskEntry+1))
	_ = f.Close()
	if err != nil {
		return "", nil, err
	}
	var disk diskBatch
	if len(data) > maxDiskEntry || json.Unmarshal(data, &disk) != nil || disk.Batch.Validate() != nil {
		return "", nil, errors.New("invalid_access_log_queue_file")
	}
	body, err := json.Marshal(disk.Batch)
	if err != nil || len(body) > MaxBatchBytes {
		return "", nil, ErrInvalidBatch
	}
	return file.name, body, nil
}

func (s *Spool) Confirm(name string, body []byte, ack Ack) error {
	batch, err := Decode(body)
	if err != nil {
		return err
	}
	if ack.ID != batch.ID || ack.Digest != Digest(body) || ack.Count != len(batch.Records) {
		return errors.New("invalid_access_log_ack")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, file := range s.files {
		if file.name == name {
			if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !os.IsNotExist(err) {
				return err
			}
			s.bytes -= file.size
			s.files = append(s.files[:i], s.files[i+1:]...)
			break
		}
	}
	state := s.state
	state.Failures = 0
	state.NextAttemptAt = 0
	return s.save(state)
}

func (s *Spool) Retry(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state
	state.Failures = min(state.Failures+1, 100)
	state.NextAttemptAt = now.Add(Backoff(state.Failures)).UnixMilli()
	return s.save(state)
}

func (s *Spool) Maintain(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.files)
	if err := s.prune(now); err != nil {
		return err
	}
	if len(s.files) != before {
		return s.save(s.state)
	}
	return nil
}
