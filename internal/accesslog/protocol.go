// Package accesslog implements the bounded, durable Xray access-log pipeline.
package accesslog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
)

const (
	FlushInterval          = 2 * time.Second
	MaxRecords             = 500
	MaxBatchBytes          = 512 << 10
	MaxMemoryBytes         = 16 << 20
	MaxDiskBytes     int64 = 1 << 30
	OfflineRetention       = 24 * time.Hour
	ArchiveRetention       = 30 * 24 * time.Hour
	ReportTimeout          = 5 * time.Second
	MaxLineBytes           = 64 << 10
	ReportPath             = "/cluster/v1/access-logs/batches"
)

var ErrInvalidBatch = errors.New("invalid_access_log_batch")

type Record struct {
	ID         string `json:"id"`
	OccurredAt int64  `json:"occurredAt"`
	CapturedAt int64  `json:"capturedAt"`
	Source     string `json:"source"`
	Target     string `json:"target"`
	Email      string `json:"email"`
	Inbound    string `json:"inbound"`
	Outbound   string `json:"outbound"`
	Category   string `json:"category"`
}

type Batch struct {
	ID        string   `json:"id"`
	CreatedAt int64    `json:"createdAt"`
	Records   []Record `json:"records"`
}

type Ack struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Count  int    `json:"count"`
}

func Digest(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func (b Batch) Validate() error {
	id, err := uuid.Parse(b.ID)
	if err != nil || id == uuid.Nil || id.String() != b.ID || b.CreatedAt <= 0 || len(b.Records) == 0 || len(b.Records) > MaxRecords {
		return ErrInvalidBatch
	}
	seen := make(map[string]bool, len(b.Records))
	for _, r := range b.Records {
		h, err := hex.DecodeString(r.ID)
		if err != nil || len(h) != 32 || seen[r.ID] || r.OccurredAt <= 0 || r.CapturedAt <= 0 {
			return ErrInvalidBatch
		}
		seen[r.ID] = true
		if r.Category != "direct" && r.Category != "blocked" && r.Category != "proxy" {
			return ErrInvalidBatch
		}
	}
	return nil
}

func Decode(data []byte) (Batch, error) {
	var b Batch
	if len(data) > MaxBatchBytes {
		return b, ErrInvalidBatch
	}
	var wire struct {
		ID        string          `json:"id"`
		CreatedAt int64           `json:"createdAt"`
		Records   json.RawMessage `json:"records"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil || d.Decode(new(any)) != io.EOF {
		return b, ErrInvalidBatch
	}
	b.ID, b.CreatedAt = wire.ID, wire.CreatedAt
	d = json.NewDecoder(bytes.NewReader(wire.Records))
	d.DisallowUnknownFields()
	if token, err := d.Token(); err != nil || token != json.Delim('[') {
		return b, ErrInvalidBatch
	}
	for d.More() {
		if len(b.Records) >= MaxRecords {
			return b, ErrInvalidBatch
		}
		var r Record
		if d.Decode(&r) != nil {
			return b, ErrInvalidBatch
		}
		b.Records = append(b.Records, r)
	}
	if _, err := d.Token(); err != nil {
		return b, ErrInvalidBatch
	}
	return b, b.Validate()
}

func Backoff(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	return min(time.Second<<min(failures-1, 6), time.Minute)
}
