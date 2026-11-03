package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/accesslog"
	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/util/netsafe"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

const settingAccessLogMaster = "accessLogMaster"

// AccessLogMaster contains public routing information only. Identity and trust
// are loaded from the existing control settings for every request.
type AccessLogMaster struct {
	GUID         string `json:"guid"`
	Address      string `json:"address"`
	Port         int    `json:"port"`
	AllowPrivate bool   `json:"allowPrivate"`
}

func (s *AccessLogService) send(ctx context.Context, body []byte) (accesslog.Ack, error) {
	settings := &SettingService{}
	self, err := settings.ControlIdentity()
	if err != nil {
		return accesslog.Ack{}, err
	}
	if self.Role == cluster.RoleMaster {
		return s.Store(ctx, self.GUID, body, time.Now())
	}
	row, err := settings.getSetting(settingAccessLogMaster)
	if database.IsNotFound(err) {
		return accesslog.Ack{}, errors.New("access_log_master_address_not_configured")
	}
	if err != nil {
		return accesslog.Ack{}, err
	}
	var target AccessLogMaster
	if json.Unmarshal([]byte(row.Value), &target) != nil {
		return accesslog.Ack{}, errors.New("invalid_access_log_master")
	}
	address, err := netsafe.NormalizeHost(target.Address)
	if err != nil || target.Port < 1 || target.Port > 65535 {
		return accesslog.Ack{}, errors.New("invalid_access_log_master")
	}
	peer, err := settings.LookupControlPeer(ctx, target.GUID)
	if err != nil {
		return accesslog.Ack{}, err
	}
	if peer.Role != cluster.RoleMaster {
		return accesslog.Ack{}, errors.New("access_log_target_is_not_master")
	}
	credentials, err := settings.EnsureControlCredentials()
	if err != nil {
		return accesslog.Ack{}, err
	}
	tlsConfig, err := cluster.ClientTLS(credentials, peer)
	if err != nil {
		return accesslog.Ack{}, err
	}
	ctx, cancel := context.WithTimeout(netsafe.ContextWithAllowPrivate(ctx, target.AllowPrivate), accesslog.ReportTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, pairingURL(address, target.Port, accesslog.ReportPath), bytes.NewReader(body))
	if err != nil {
		return accesslog.Ack{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: netsafe.SSRFGuardedDialContext, ResponseHeaderTimeout: accesslog.ReportTimeout}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: accesslog.ReportTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return accesslog.Ack{}, errors.New("access_log_master_unreachable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return accesslog.Ack{}, errors.New("access_log_report_rejected")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(data) > 8192 {
		return accesslog.Ack{}, errors.New("invalid_access_log_ack")
	}
	var ack accesslog.Ack
	if json.Unmarshal(data, &ack) != nil {
		return ack, errors.New("invalid_access_log_ack")
	}
	return ack, nil
}

type accessLogSource struct {
	stamp           time.Time
	size            int64
	path            string
	direct, blocked []string
}

func (source *accessLogSource) refresh() error {
	info, err := os.Stat(xray.GetConfigPath())
	if os.IsNotExist(err) {
		source.path = ""
		return nil
	}
	if err != nil {
		return err
	}
	if info.ModTime() == source.stamp && info.Size() == source.size {
		return nil
	}
	path, err := xray.GetAccessLogPath()
	if err != nil {
		return err
	}
	source.path = path
	source.stamp = info.ModTime()
	source.size = info.Size()
	source.direct, source.blocked = (&ServerService{}).GetDefaultLogOutboundTags()
	return nil
}

func (source *accessLogSource) parse(line string, now time.Time) (accesslog.Record, bool) {
	entry := parseAccessLogFields(line)
	if entry.DateTime.IsZero() {
		return accesslog.Record{}, false
	}
	category := "proxy"
	if strings.Contains(line, " rejected ") {
		category = "blocked"
		if entry.ToAddress == "" {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "rejected" && i+1 < len(parts) {
					entry.ToAddress = parts[i+1]
					break
				}
			}
		}
	} else if logEntryContains(line, source.direct) {
		category = "direct"
	} else if logEntryContains(line, source.blocked) {
		category = "blocked"
	}
	if entry.FromAddress == "" || entry.ToAddress == "" {
		return accesslog.Record{}, false
	}
	return accesslog.Record{OccurredAt: entry.DateTime.UnixMilli(), Source: entry.FromAddress, Target: entry.ToAddress, Email: entry.Email, Inbound: entry.Inbound, Outbound: entry.Outbound, Category: category}, true
}

// RunAccessLogWorker owns collector/reporter lifetimes. A broken log path or
// full/unavailable spool does not stop proxy services. Cancellation is joined
// before the server closes its database or replaces the worker on restart.
func RunAccessLogWorker(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		var warningMu sync.Mutex
		var lastWarning time.Time
		warn := func(error) {
			warningMu.Lock()
			defer warningMu.Unlock()
			if time.Since(lastWarning) >= time.Minute {
				logger.Warning("Access log pipeline unavailable; queued records remain subject to retention and capacity limits")
				lastWarning = time.Now()
			}
		}
		var spool *accesslog.Spool
		for ctx.Err() == nil {
			var err error
			spool, err = accesslog.OpenSpool(filepath.Join(config.GetDBFolderPath(), "access-log-spool"), time.Now())
			if err == nil {
				break
			}
			warn(err)
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			return
		}
		service := &AccessLogService{}
		reportDone := make(chan struct{})
		go func() { defer close(reportDone); accesslog.Report(ctx, spool, service.send, warn) }()
		defer func() { <-reportDone }()
		pruneDone := make(chan struct{})
		go func() {
			defer close(pruneDone)
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for ctx.Err() == nil {
				if err := service.Prune(ctx, time.Now()); err != nil {
					warn(err)
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
		defer func() { <-pruneDone }()
		source := &accessLogSource{}
		reader := &accesslog.Tailer{Spool: spool, Parse: source.parse, StartAtEnd: true}
		defer reader.Close()
		for ctx.Err() == nil {
			now := time.Now()
			reader.More = false
			if err := spool.Maintain(now); err != nil {
				warn(err)
			}
			if err := source.refresh(); err != nil {
				warn(err)
			} else if err := reader.Poll(source.path, now); err != nil {
				warn(err)
			}
			if reader.More {
				continue
			}
			timer := time.NewTimer(accesslog.FlushInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return done
}
