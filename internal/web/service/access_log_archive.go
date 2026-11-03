package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/accesslog"
	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

var accessArchiveGate = make(chan struct{}, 1)
var accessReceiveGate = make(chan struct{}, 2)

func lockAccessArchive(ctx context.Context) error {
	select {
	case accessArchiveGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type AccessLogService struct{}

func accessLogAddress(value string) (network, host string, port int) {
	for _, prefix := range []string{"tcp:", "udp:"} {
		if strings.HasPrefix(value, prefix) {
			network = strings.TrimSuffix(prefix, ":")
			value = strings.TrimPrefix(value, prefix)
			break
		}
	}
	host, raw, err := net.SplitHostPort(value)
	if err != nil {
		return network, value, 0
	}
	port, _ = strconv.Atoi(raw)
	if port < 1 || port > 65535 {
		port = 0
	}
	return network, host, port
}

func accessArchiveRow(guid string, r accesslog.Record, now time.Time) model.AccessLog {
	_, source, _ := accessLogAddress(r.Source)
	source, _, _ = strings.Cut(source, "%")
	sourceIP := ""
	if ip := net.ParseIP(source); ip != nil {
		sourceIP = ip.String()
	}
	network, target, port := accessLogAddress(r.Target)
	return model.AccessLog{NodeGUID: guid, EventID: r.ID, OccurredAt: r.OccurredAt, ReceivedAt: now.UnixMilli(), Source: r.Source, Target: r.Target, SourceIP: sourceIP, TargetHost: target, TargetPort: port, Network: network, Email: r.Email, Inbound: r.Inbound, Outbound: r.Outbound, Category: r.Category}
}

func accessDB() *gorm.DB { return database.GetDB().Session(&gorm.Session{Logger: logger.Discard}) }

// Store acknowledges only a committed archive/receipt transaction. The source
// is supplied by verified mTLS or the local collector, never the request body.
func (s *AccessLogService) Store(ctx context.Context, guid string, body []byte, now time.Time) (accesslog.Ack, error) {
	batch, err := accesslog.Decode(body)
	if err != nil {
		return accesslog.Ack{}, err
	}
	if (cluster.Identity{GUID: guid, Role: cluster.RoleSlave}).Validate() != nil {
		return accesslog.Ack{}, accesslog.ErrInvalidBatch
	}
	ack := accesslog.Ack{ID: batch.ID, Digest: accesslog.Digest(body), Count: len(batch.Records)}
	if err := lockAccessArchive(ctx); err != nil {
		return accesslog.Ack{}, err
	}
	defer func() { <-accessArchiveGate }()
	err = accessDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var receipt model.AccessLogReceipt
		err := tx.Where("node_guid = ? AND batch_id = ?", guid, batch.ID).First(&receipt).Error
		if err == nil {
			if receipt.Digest != ack.Digest || receipt.Count != ack.Count {
				return errors.New("access_log_batch_conflict")
			}
			return nil
		}
		if !database.IsNotFound(err) {
			return err
		}
		rows := make([]model.AccessLog, 0, len(batch.Records))
		for _, r := range batch.Records {
			if r.OccurredAt < now.Add(-accesslog.ArchiveRetention).UnixMilli() {
				continue
			}
			rows = append(rows, accessArchiveRow(guid, r, now))
		}
		if len(rows) > 0 {
			if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "node_guid"}, {Name: "event_id"}}, DoNothing: true}).CreateInBatches(rows, 50).Error; err != nil {
				return err
			}
		}
		created := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "node_guid"}, {Name: "batch_id"}}, DoNothing: true}).Create(&model.AccessLogReceipt{NodeGUID: guid, BatchID: batch.ID, Digest: ack.Digest, Count: ack.Count, ReceivedAt: now.UnixMilli()})
		if created.Error != nil {
			return created.Error
		}
		if created.RowsAffected == 0 {
			if err := tx.Where("node_guid = ? AND batch_id = ?", guid, batch.ID).First(&receipt).Error; err != nil {
				return err
			}
			if receipt.Digest != ack.Digest || receipt.Count != ack.Count {
				return errors.New("access_log_batch_conflict")
			}
		}
		return nil
	})
	return ack, err
}

func (s *AccessLogService) Prune(ctx context.Context, now time.Time) error {
	if err := lockAccessArchive(ctx); err != nil {
		return err
	}
	defer func() { <-accessArchiveGate }()
	cutoff := now.Add(-accesslog.ArchiveRetention).UnixMilli()
	return accessDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("occurred_at < ? OR received_at < ?", cutoff, cutoff).Delete(&model.AccessLog{}).Error; err != nil {
			return err
		}
		return tx.Where("received_at < ?", cutoff).Delete(&model.AccessLogReceipt{}).Error
	})
}

func (s *AccessLogService) RegisterControlRoutes(router *cluster.Router) {
	router.HandleSlave("POST "+accesslog.ReportPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := cluster.AuthenticatedPeer(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		select {
		case accessReceiveGate <- struct{}{}:
			defer func() { <-accessReceiveGate }()
		case <-r.Context().Done():
			return
		}
		var count int64
		if err := accessDB().Model(&model.Node{}).Where("guid = ? AND control_connection = ?", identity.GUID, true).Count(&count).Error; err != nil {
			http.Error(w, "access_log_storage_unavailable", 503)
			return
		}
		if count != 1 {
			http.Error(w, "access_log_node_not_registered", 403)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, accesslog.MaxBatchBytes))
		if err != nil {
			http.Error(w, "access_log_batch_too_large", http.StatusRequestEntityTooLarge)
			return
		}
		ack, err := s.Store(r.Context(), identity.GUID, body, time.Now())
		if err != nil {
			status := http.StatusInternalServerError
			code := "access_log_storage_unavailable"
			if errors.Is(err, accesslog.ErrInvalidBatch) {
				status = 400
				code = "invalid_access_log_batch"
			}
			if err.Error() == "access_log_batch_conflict" {
				status = 409
				code = "access_log_batch_conflict"
			}
			http.Error(w, code, status)
			return
		}
		pairingJSON(w, ack, nil)
	}))
}
