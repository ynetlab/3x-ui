package accesslog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Parser func(string, time.Time) (Record, bool)

type Tailer struct {
	Spool      *Spool
	Parse      Parser
	StartAtEnd bool
	More       bool
	file       *os.File
	path       string
}

func (t *Tailer) Close() {
	if t.file != nil {
		_ = t.file.Close()
		t.file = nil
	}
}

func regularOpen(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("access_log_not_regular_file")
	}
	return openLog(path)
}

// locate resumes a renamed file after a restart before switching to its new
// replacement. Directory entries are streamed, rather than retained in memory.
func locate(path, id string) (*os.File, error) {
	f, err := regularOpen(path)
	if err == nil {
		current, e := fileID(f)
		if e != nil {
			f.Close()
			return nil, e
		}
		if current == id {
			return f, nil
		}
		f.Close()
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	base := filepath.Base(path)
	for {
		entries, err := dir.ReadDir(128)
		if err != nil && err != io.EOF {
			return nil, err
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), base+".") || !entry.Type().IsRegular() {
				continue
			}
			f, e := regularOpen(filepath.Join(filepath.Dir(path), entry.Name()))
			if e != nil {
				continue
			}
			found, e := fileID(f)
			if e == nil && found == id {
				return f, nil
			}
			f.Close()
		}
		if err == io.EOF {
			break
		}
	}
	return regularOpen(path)
}

func hashAt(f *os.File, offset int64, n int) (string, error) {
	if n == 0 {
		return "", nil
	}
	b := make([]byte, n)
	_, err := f.ReadAt(b, offset)
	if err != nil {
		return "", err
	}
	return Digest(b), nil
}

func anchors(f *os.File, c Cursor) (Cursor, error) {
	var err error
	c.PrefixBytes = int(min(c.Offset, 128))
	c.PrefixHash, err = hashAt(f, 0, c.PrefixBytes)
	if err != nil {
		return c, err
	}
	c.AnchorBytes = int(min(c.Offset, 128))
	c.AnchorHash, err = hashAt(f, c.Offset-int64(c.AnchorBytes), c.AnchorBytes)
	return c, err
}

func unchanged(f *os.File, c Cursor) bool {
	info, err := f.Stat()
	if err != nil || info.Size() < c.Offset || c.Offset < 0 {
		return false
	}
	p, e := hashAt(f, 0, c.PrefixBytes)
	if e != nil || p != c.PrefixHash {
		return false
	}
	a, e := hashAt(f, c.Offset-int64(c.AnchorBytes), c.AnchorBytes)
	return e == nil && a == c.AnchorHash
}

func (t *Tailer) Poll(path string, now time.Time) error {
	t.More = false
	if path == "" || strings.EqualFold(path, "none") {
		t.Close()
		return nil
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	c := t.Spool.Snapshot().Cursor
	if t.file != nil && t.path != path {
		t.Close()
	}
	if t.file == nil {
		if c.Path == path && c.FileID != "" {
			t.file, err = locate(path, c.FileID)
		} else {
			t.file, err = regularOpen(path)
		}
		if os.IsNotExist(err) {
			if c.Path == "" {
				if err := t.Spool.Commit(nil, Cursor{Path: path}, Statistics{}, now); err != nil {
					return err
				}
			}
			return nil
		}
		if err != nil {
			return err
		}
		t.path = path
	}
	id, err := fileID(t.file)
	if err != nil {
		return err
	}
	if c.Path != path || c.FileID != id || c.Generation == "" || !unchanged(t.file, c) {
		fresh := c.Path == ""
		c = Cursor{Path: path, FileID: id, Generation: uuid.NewString()}
		if fresh && t.StartAtEnd {
			info, err := t.file.Stat()
			if err != nil {
				return err
			}
			c.Offset = info.Size()
			if c.Offset > 0 {
				var last [1]byte
				if _, err := t.file.ReadAt(last[:], c.Offset-1); err != nil {
					return err
				}
				c.Skipping = last[0] != '\n'
			}
		}
		c, err = anchors(t.file, c)
		if err != nil {
			return err
		}
		// Persist the generation before any event can be reported. A crash after
		// a batch write but before its checkpoint then replays the same IDs.
		if err := t.Spool.Commit(nil, c, Statistics{}, now); err != nil {
			return err
		}
	}
	if _, err = t.file.Seek(c.Offset, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(t.file, MaxLineBytes)
	var records []Record
	var stats Statistics
	bytesUsed := 128 // UUID, timestamp, field names, delimiters.
	processed := 0
	committed := c.Offset
	flush := func() error {
		next, err := anchors(t.file, c)
		if err != nil { // Preserve complete lines already read across a concurrent truncation.
			next = c
			next.AnchorBytes = 1
			next.AnchorHash = "invalidated"
		}
		if err := t.Spool.Commit(records, next, stats, now); err != nil {
			return err
		}
		c = next
		committed = c.Offset
		records = nil
		stats = Statistics{}
		bytesUsed = 128
		return nil
	}
	for processed < 8<<20 { // Bound work per poll; backlog continues next poll.
		before := c
		line, readErr := reader.ReadSlice('\n')
		processed += len(line)
		if readErr == bufio.ErrBufferFull {
			if !c.Skipping {
				stats.Oversized++
			}
			c.Skipping = true
			c.Offset += int64(len(line))
			continue
		}
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		if readErr == io.EOF {
			if c.Skipping {
				c.Offset += int64(len(line))
			}
			if len(line) > 0 && !c.Skipping {
				current, e := regularOpen(path)
				if e == nil {
					newID, e := fileID(current)
					current.Close()
					if e == nil && newID != id {
						c.Offset += int64(len(line))
						stats.Malformed++
					}
				}
			}
			// A partial final line remains at its starting offset until completed.
			break
		}
		c.Offset += int64(len(line))
		if c.Skipping {
			c.Skipping = false
			continue
		}
		text := strings.TrimSpace(string(line))
		if text == "" || strings.Contains(text, "api -> api") {
			continue
		}
		r, ok := t.Parse(text, now)
		if !ok {
			stats.Malformed++
			continue
		}
		if r.OccurredAt < now.Add(-ArchiveRetention).UnixMilli() {
			continue
		}
		// The existing parser returns substrings of the source line. Detach
		// selected fields so a tiny event cannot retain an entire 64 KiB line.
		r.Source = strings.Clone(r.Source)
		r.Target = strings.Clone(r.Target)
		r.Email = strings.Clone(r.Email)
		r.Inbound = strings.Clone(r.Inbound)
		r.Outbound = strings.Clone(r.Outbound)
		r.ID = Digest([]byte(fmt.Sprintf("%s:%d:%s", c.Generation, before.Offset, text)))
		r.CapturedAt = now.UnixMilli()
		encoded, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if len(encoded)+128 > MaxBatchBytes {
			stats.Oversized++
			continue
		}
		if len(records) >= MaxRecords || bytesUsed+len(encoded)+1 > MaxBatchBytes {
			after := c
			c = before
			if err := flush(); err != nil {
				return err
			}
			c = after
		}
		records = append(records, r)
		bytesUsed += len(encoded) + 1
	}
	if c.Offset != committed || len(records) > 0 || stats.Malformed > 0 || stats.Oversized > 0 {
		if err := flush(); err != nil {
			return err
		}
	}
	// Drain an open renamed file before opening the replacement. At EOF this
	// also tolerates a temporarily missing current path during log rotation.
	info, err := t.file.Stat()
	if err != nil {
		return err
	}
	if c.Offset >= info.Size() {
		current, e := regularOpen(path)
		if e == nil {
			newID, e := fileID(current)
			if e == nil && newID != id {
				next := Cursor{Path: path, FileID: newID, Generation: uuid.NewString()}
				if err := t.Spool.Commit(nil, next, Statistics{}, now); err != nil {
					current.Close()
					return err
				}
				t.Close()
				t.file = current
				t.More = true
			} else {
				current.Close()
			}
		}
	} else if processed >= 8<<20 {
		t.More = true
	}
	return nil
}
