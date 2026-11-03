package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/cloudflare"
	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/nodeip"
	"github.com/mhsanaei/3x-ui/v3/internal/util/netsafe"
)

// The public master route saved by pairing is shared with log reporting. Trust
// and the active identity always come from the existing control settings.
func reportNodeIP(ctx context.Context, probe func(context.Context) nodeip.Report) error {
	settings := &SettingService{}
	row, err := settings.getSetting(settingAccessLogMaster)
	if err != nil {
		return err
	}
	var target AccessLogMaster
	if json.Unmarshal([]byte(row.Value), &target) != nil {
		return errors.New("node_ip_master_not_configured")
	}
	host, err := netsafe.NormalizeHost(target.Address)
	if err != nil || target.Port < 1 || target.Port > 65535 {
		return errors.New("node_ip_master_not_configured")
	}
	peer, err := settings.LookupControlPeer(ctx, target.GUID)
	if err != nil || peer.Role != cluster.RoleMaster {
		return errors.New("node_ip_master_not_trusted")
	}
	credentials, err := settings.EnsureControlCredentials()
	if err != nil {
		return err
	}
	tlsConfig, err := cluster.ClientTLS(credentials, peer)
	if err != nil {
		return err
	}
	report := probe(ctx)
	body, _ := json.Marshal(report)
	ctx, cancel := context.WithTimeout(netsafe.ContextWithAllowPrivate(ctx, target.AllowPrivate), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pairingURL(host, target.Port, nodeip.ReportPath), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: netsafe.SSRFGuardedDialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("node_ip_master_unreachable")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1025))
	if err != nil || len(data) > 1024 || resp.StatusCode != 200 {
		return errors.New("node_ip_report_rejected")
	}
	var ack struct {
		Accepted   bool  `json:"accepted"`
		ObservedAt int64 `json:"observedAt"`
	}
	if json.Unmarshal(data, &ack) != nil || !ack.Accepted || ack.ObservedAt != report.ObservedAt {
		return errors.New("node_ip_invalid_ack")
	}
	return nil
}

func (s *CloudflareDNSService) syncBinding(ctx context.Context, id int64, now time.Time) error {
	if err := lockCloudflareDNS(ctx); err != nil {
		return err
	}
	defer func() { <-cloudflareDNSGate }()
	var binding model.NodeDNSBinding
	if err := dnsDB().WithContext(ctx).First(&binding, id).Error; err != nil {
		return err
	}
	var address model.NodePublicIP
	if err := dnsDB().WithContext(ctx).Where("node_id = ? AND node_guid = ?", binding.NodeID, binding.NodeGUID).First(&address).Error; err != nil {
		if database.IsNotFound(err) {
			return nil
		}
		return err
	}
	if address.ReceivedAt < now.Add(-2*nodeip.Interval).UnixMilli() {
		return nil
	}
	ip := ""
	if binding.Type == "A" && address.IPv4Available {
		ip = address.IPv4
	}
	if binding.Type == "AAAA" && address.IPv6Available {
		ip = address.IPv6
	}
	if ip == "" || ip == binding.Content {
		return nil
	}
	if _, err := nodeip.PublicIP(ip, binding.Type == "A"); err != nil {
		return err
	}
	var count int64
	if err := dnsDB().WithContext(ctx).Model(&model.Node{}).Where("id = ? AND guid = ? AND control_connection = ?", binding.NodeID, binding.NodeGUID, true).Count(&count).Error; err != nil {
		return err
	}
	if count != 1 {
		return nil
	}
	peer, err := (&SettingService{}).LookupControlPeer(ctx, binding.NodeGUID)
	if err != nil || peer.Role != cluster.RoleSlave {
		return nil
	}
	d, err := s.session(ctx, binding.NodeID)
	if err != nil {
		return err
	}
	if d.zone.ID != binding.ZoneID {
		return nil
	}
	current, err := d.client.Get(ctx, binding.ZoneID, binding.RecordID)
	if err != nil {
		return err
	}
	if current.Type != binding.Type {
		return dnsError(409, "cloudflare_record_changed")
	}
	if current.Content != ip {
		current, err = d.client.Update(ctx, binding.ZoneID, binding.RecordID, map[string]any{"content": ip})
		if err != nil {
			return err
		}
	}
	if current.Content != ip || current.Type != binding.Type {
		return dnsError(502, "cloudflare_invalid_response")
	}
	_, err = d.saveBinding(ctx, current)
	if err != nil {
		return err
	}
	return dnsDB().WithContext(ctx).Model(&binding).Updates(map[string]any{"last_sync_error": "", "last_synced_at": now.UnixMilli()}).Error
}

func (s *CloudflareDNSService) Sync(ctx context.Context, now time.Time) error {
	role, err := (&SettingService{}).GetPanelRole()
	if err != nil {
		return err
	}
	if role != PanelRoleMaster {
		return nil
	}
	zone, err := (&SettingService{}).getString("cloudflareZoneId")
	if err != nil {
		return err
	}
	if zone == "" {
		return nil
	}
	token, err := (&SettingService{}).GetCloudflareAPIToken()
	if err != nil {
		return err
	}
	if token == "" {
		return nil
	}
	var ids []int64
	if err := dnsDB().WithContext(ctx).Model(&model.NodeDNSBinding{}).Where("zone_id = ?", zone).Order("id ASC").Pluck("id", &ids).Error; err != nil {
		return err
	}
	var first error
	for _, id := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.syncBinding(ctx, id, now); err != nil {
			if first == nil {
				first = err
			}
			code := "cloudflare_sync_failed"
			var local *CloudflareDNSError
			var provider *cloudflare.Error
			if errors.As(err, &local) {
				code = local.Code
			} else if errors.As(err, &provider) {
				code = provider.Code
			}
			_ = dnsDB().WithContext(ctx).Model(&model.NodeDNSBinding{}).Where("id = ?", id).Update("last_sync_error", code).Error
			if errors.As(err, &provider) && (provider.Code == "cloudflare_auth_failed" || provider.Code == "cloudflare_rate_limited") {
				break
			}
		}
	}
	return first
}

func RunNodeDNSWorker(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(nodeip.Interval)
		defer ticker.Stop()
		var lastWarning time.Time
		for ctx.Err() == nil {
			cycle, cancel := context.WithTimeout(ctx, 55*time.Second)
			role, err := (&SettingService{}).GetPanelRole()
			if err == nil {
				if role == PanelRoleSlave {
					err = reportNodeIP(cycle, nodeip.Probe)
				} else {
					err = (&CloudflareDNSService{}).Sync(cycle, time.Now())
				}
			}
			cancel()
			if err != nil && ctx.Err() == nil && time.Since(lastWarning) >= time.Minute {
				// Pending installations have no master route yet; they do not probe.
				if role == PanelRoleMaster {
					logger.Warning("Node DNS synchronization unavailable; existing records are retained")
				} else if route, loadErr := (&SettingService{}).getString(settingAccessLogMaster); loadErr == nil && route != "" {
					logger.Warning("Node public IP report unavailable; waiting for the next detection cycle")
				}
				lastWarning = time.Now()
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-nodeIPWake:
			}
		}
	}()
	return done
}
