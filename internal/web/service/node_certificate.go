package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/mhsanaei/3x-ui/v3/internal/cloudflare"
	"github.com/mhsanaei/3x-ui/v3/internal/crypto/nodetoken"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/panelcert"
	"github.com/mhsanaei/3x-ui/v3/internal/util/netsafe"
)

var (
	certificateJobMu  sync.Mutex
	certificateStepMu sync.Mutex
	certificateWake   = make(chan struct{}, 1)
)

type NodeCertificateService struct {
	dnsClient func(string) *cloudflare.Client
	dnsWait   func(context.Context, string, string) error
	issuer    func(context.Context, []string, panelcert.DNSChallenge) (panelcert.Bundle, error)
	roots     *x509.CertPool
	deploy    func(context.Context, *model.NodeCertificateJob, panelcert.Bundle) error
}

type CertificateRequest struct {
	RecordIDs     []string `json:"recordIds"`
	PrimaryDomain string   `json:"primaryDomain"`
}

type CertificateView struct {
	ID                string   `json:"id"`
	NodeID            int      `json:"nodeId"`
	Status            string   `json:"status"`
	Domains           []string `json:"domains"`
	PrimaryDomain     string   `json:"primaryDomain"`
	Fingerprint       string   `json:"fingerprint"`
	ExpiresAt         int64    `json:"expiresAt"`
	ActiveExpiresAt   int64    `json:"activeExpiresAt"`
	ActiveFingerprint string   `json:"activeFingerprint"`
	NextAttemptAt     int64    `json:"nextAttemptAt"`
	LastError         string   `json:"lastError"`
	UpdatedAt         int64    `json:"updatedAt"`
}

func certificateView(row model.NodeCertificateJob) CertificateView {
	domains := []string{}
	_ = json.Unmarshal([]byte(row.Domains), &domains)
	return CertificateView{ID: row.ID, NodeID: row.NodeID, Status: row.Status, Domains: domains, PrimaryDomain: row.PrimaryDomain, Fingerprint: row.Fingerprint, ExpiresAt: row.ExpiresAt, NextAttemptAt: row.NextAttemptAt, LastError: row.LastError, UpdatedAt: row.UpdatedAt}
}

func certificateNode(ctx context.Context, id int) (model.Node, error) {
	if err := requireCertificateMaster(); err != nil {
		return model.Node{}, err
	}
	var node model.Node
	if id < 1 {
		return node, pairingError(400, "invalid_certificate_node")
	}
	if err := pairingDB().WithContext(ctx).First(&node, id).Error; err != nil {
		return node, err
	}
	if !node.ControlConnection || !validPairingID(node.Guid) {
		return node, pairingError(409, "certificate_requires_paired_node")
	}
	if _, err := (&SettingService{}).ControlTLSForNode(&node); err != nil {
		return node, pairingError(409, "certificate_node_trust_changed")
	}
	return node, nil
}

func (s *NodeCertificateService) Status(ctx context.Context, id int) (CertificateView, error) {
	node, err := certificateNode(ctx, id)
	if err != nil {
		return CertificateView{}, err
	}
	var row model.NodeCertificateJob
	err = pairingDB().WithContext(ctx).Where("node_id = ? AND node_guid = ?", id, node.Guid).Order("created_at DESC, id DESC").First(&row).Error
	if database.IsNotFound(err) {
		return CertificateView{NodeID: id, Status: "none", Domains: []string{}}, nil
	}
	if err != nil {
		return CertificateView{}, err
	}
	view := certificateView(row)
	var active model.NodeCertificateJob
	if err := pairingDB().WithContext(ctx).Where("node_id = ? AND node_guid = ? AND active = ?", id, node.Guid, true).First(&active).Error; err == nil {
		view.ActiveExpiresAt = active.ExpiresAt
		view.ActiveFingerprint = active.Fingerprint
	} else if !database.IsNotFound(err) {
		return CertificateView{}, err
	}
	return view, nil
}

func certificateDomains(input []string, primary, zone string) ([]string, string, error) {
	set := map[string]bool{}
	if len(input) < 1 || len(input) > 100 {
		return nil, "", pairingError(400, "invalid_certificate_domains")
	}
	for _, value := range input {
		domain, err := dnsName(value, true)
		if err != nil || domain != zone && !strings.HasSuffix(domain, "."+zone) {
			return nil, "", pairingError(400, "acme_domain_outside_zone")
		}
		set[domain] = true
	}
	primary, err := dnsName(primary, false)
	if err != nil || !set[primary] {
		return nil, "", pairingError(400, "invalid_certificate_primary_domain")
	}
	domains := make([]string, 0, len(set))
	for domain := range set {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains, primary, nil
}

func (s *NodeCertificateService) validateRecords(ctx context.Context, d *dnsSession, ids []string, primary string) ([]string, error) {
	if len(ids) < 1 || len(ids) > 200 {
		return nil, pairingError(400, "invalid_certificate_records")
	}
	names := []string{}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		binding, err := d.binding(ctx, id)
		if err != nil {
			return nil, err
		}
		record, err := d.client.Get(ctx, d.zone.ID, id)
		if err != nil {
			return nil, err
		}
		if record.Name != binding.Name || record.Type != binding.Type || record.Content != binding.Content || record.TTL != binding.TTL || record.Proxied != binding.Proxied || record.Type != "A" && record.Type != "AAAA" {
			return nil, pairingError(409, "certificate_dns_record_changed")
		}
		names = append(names, record.Name)
	}
	domains, _, err := certificateDomains(names, primary, d.zone.Name)
	return domains, err
}

func (s *NodeCertificateService) Request(ctx context.Context, id int, req CertificateRequest) (CertificateView, error) {
	certificateJobMu.Lock()
	defer certificateJobMu.Unlock()
	node, err := certificateNode(ctx, id)
	if err != nil {
		return CertificateView{}, err
	}
	config, err := s.Config()
	if err != nil {
		return CertificateView{}, err
	}
	if config.Email == "" || !config.AcceptTOS {
		return CertificateView{}, pairingError(409, "acme_not_configured")
	}
	d, err := s.configuredDNS(ctx)
	if err != nil {
		return CertificateView{}, err
	}
	d.node = node
	domains, err := s.validateRecords(ctx, d, req.RecordIDs, req.PrimaryDomain)
	if err != nil {
		return CertificateView{}, err
	}
	domainData, _ := json.Marshal(domains)
	idData, _ := json.Marshal(req.RecordIDs)
	primary, err := dnsName(req.PrimaryDomain, false)
	if err != nil {
		return CertificateView{}, err
	}
	job := model.NodeCertificateJob{ID: uuid.NewString(), NodeID: node.Id, NodeGUID: node.Guid, ActiveSlot: &node.Guid, ZoneID: d.zone.ID, Domains: string(domainData), RecordIDs: string(idData), PrimaryDomain: primary, Status: "queued"}
	if err := pairingDB().Create(&job).Error; err != nil {
		return CertificateView{}, pairingError(409, "certificate_job_busy")
	}
	wakeCertificateWorker()
	return certificateView(job), nil
}

func (s *NodeCertificateService) Retry(ctx context.Context, id int) (CertificateView, error) {
	node, err := certificateNode(ctx, id)
	if err != nil {
		return CertificateView{}, err
	}
	if err := pairingDB().WithContext(ctx).Model(&model.NodeCertificateJob{}).Where("node_id = ? AND node_guid = ? AND active_slot IS NOT NULL", id, node.Guid).Updates(map[string]any{"next_attempt_at": 0}).Error; err != nil {
		return CertificateView{}, err
	}
	wakeCertificateWorker()
	return s.Status(ctx, id)
}

func wakeCertificateWorker() {
	select {
	case certificateWake <- struct{}{}:
	default:
	}
}

func sealCertificateBundle(id string, bundle panelcert.Bundle) (string, error) {
	data, err := json.Marshal(bundle)
	if err != nil {
		return "", err
	}
	return nodetoken.EncryptBound([]byte("node-certificate/"+id), string(data))
}

func openCertificateBundle(row *model.NodeCertificateJob) (panelcert.Bundle, error) {
	var bundle panelcert.Bundle
	if nodetoken.IsEncrypted(row.Payload) && !nodetoken.Enabled() {
		return bundle, errors.New("certificate_key_unavailable")
	}
	data, err := nodetoken.DecryptBound([]byte("node-certificate/"+row.ID), row.Payload)
	if err == nil {
		err = json.Unmarshal([]byte(data), &bundle)
	}
	return bundle, err
}

func certificateFailureCode(err error) string {
	var pe *PairingError
	var cf *cloudflare.Error
	var dns *CloudflareDNSError
	switch {
	case errors.As(err, &pe):
		return pe.Code
	case errors.As(err, &cf):
		return cf.Code
	case errors.As(err, &dns):
		return dns.Code
	}
	for _, code := range []string{"acme_account_failed", "acme_order_failed", "acme_authorization_failed", "acme_dns01_unavailable", "acme_challenge_failed", "acme_dns_propagation_failed", "acme_finalize_failed", "invalid_panel_certificate", "panel_certificate_reload_unavailable", "certificate_key_unavailable", "acme_account_unavailable"} {
		if err.Error() == code {
			return code
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "certificate_request_timeout"
	}
	return "certificate_operation_failed"
}

type certificateTarget struct {
	address      string
	port         int
	token        string
	allowPrivate bool
	tls          *tls.Config
	enrollment   string
	deferConfirm bool
}

func (s *NodeCertificateService) target(ctx context.Context, job *model.NodeCertificateJob) (certificateTarget, error) {
	if job.NodeID == 0 && job.EnrollmentID != "" {
		return s.enrollmentTarget(ctx, job)
	}
	node, err := certificateNode(ctx, job.NodeID)
	if err != nil || node.Guid != job.NodeGUID {
		return certificateTarget{}, pairingError(409, "certificate_node_trust_changed")
	}
	config, err := (&SettingService{}).ControlTLSForNode(&node)
	if err != nil {
		return certificateTarget{}, err
	}
	token, err := nodetoken.Decrypt(node.Id, node.ApiToken)
	if err != nil || token == "" {
		return certificateTarget{}, pairingError(409, "full_admin_token_required")
	}
	return certificateTarget{address: node.Address, port: node.Port, token: token, allowPrivate: node.AllowPrivateAddress, tls: config}, nil
}

func (s *NodeCertificateService) deployBundle(ctx context.Context, job *model.NodeCertificateJob, bundle panelcert.Bundle) error {
	if s.deploy != nil {
		return s.deploy(ctx, job, bundle)
	}
	target, err := s.target(ctx, job)
	if err != nil {
		return err
	}
	request := CertificateInstallRequest{ID: job.ID, EnrollmentID: target.enrollment, Bundle: &bundle}
	rpc := func(operation string) (CertificateInstallReceipt, error) {
		var receipt CertificateInstallReceipt
		err := pairingRPC(ctx, target.tls, target.allowPrivate, pairingURL(target.address, target.port, "/cluster/v1/certificates/"+operation), target.token, request, &receipt)
		if err == nil && (receipt.ID != job.ID || receipt.Fingerprint != job.Fingerprint || receipt.PanelPort < 1 || receipt.PanelPort > 65535) {
			err = pairingError(502, "invalid_certificate_receipt")
		}
		return receipt, err
	}
	if _, err := rpc("stage"); err != nil {
		return err
	}
	request.Bundle = nil
	receipt, err := rpc("activate")
	if err != nil {
		return err
	}
	// Connect directly to the node, using the selected domain as SNI. This
	// also works when other SANs are proxied through Cloudflare.
	probeCtx, cancel := context.WithTimeout(netsafe.ContextWithAllowPrivate(ctx, target.allowPrivate), 5*time.Second)
	conn, err := netsafe.SSRFGuardedDialContext(probeCtx, "tcp", net.JoinHostPort(target.address, strconv.Itoa(receipt.PanelPort)))
	if err == nil {
		client := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: job.PrimaryDomain, RootCAs: s.roots})
		err = client.HandshakeContext(probeCtx)
		if err == nil && (len(client.ConnectionState().PeerCertificates) == 0 || panelcert.Fingerprint(client.ConnectionState().PeerCertificates[0]) != job.Fingerprint) {
			err = errors.New("certificate_fingerprint_mismatch")
		}
		_ = client.Close()
	}
	cancel()
	if err != nil {
		// A lost rollback request is handled by the slave's confirmation lease.
		_, _ = rpc("rollback")
		return pairingError(503, "certificate_callback_failed")
	}
	if target.deferConfirm {
		return nil
	}
	confirmed, err := rpc("confirm")
	if err != nil {
		return err
	}
	if confirmed.Phase != "committed" {
		return pairingError(502, "invalid_certificate_receipt")
	}
	return nil
}

func (s *NodeCertificateService) step(ctx context.Context, id string) error {
	certificateStepMu.Lock()
	defer certificateStepMu.Unlock()
	var job model.NodeCertificateJob
	if err := pairingDB().Where("id = ? AND active_slot IS NOT NULL", id).First(&job).Error; err != nil {
		return err
	}
	d, err := s.configuredDNS(ctx)
	if err != nil {
		return s.fail(&job, err)
	}
	if d.zone.ID != job.ZoneID {
		return s.fail(&job, pairingError(409, "certificate_zone_changed"))
	}
	provider := &certificateDNSChallenge{session: d, job: job.ID}
	var leftovers []model.ACMEChallenge
	if err := pairingDB().Where("job_id = ?", job.ID).Find(&leftovers).Error; err != nil {
		return s.fail(&job, err)
	}
	for _, row := range leftovers {
		if err := provider.Clean(ctx, row.ID); err != nil {
			return s.fail(&job, err)
		}
	}
	if _, err := s.target(ctx, &job); err != nil && s.deploy == nil {
		var pe *PairingError
		if errors.As(err, &pe) && (pe.Status == 410 || pe.Code == "certificate_node_trust_changed") {
			return pairingDB().Model(&job).Updates(map[string]any{"status": "cancelled", "active_slot": nil, "payload": "", "acme_state": "", "last_error": pe.Code}).Error
		}
		return s.fail(&job, err)
	}
	var domains []string
	if err := json.Unmarshal([]byte(job.Domains), &domains); err != nil {
		return s.fail(&job, err)
	}
	if job.NodeID == 0 {
		if err := s.provisionEnrollmentDNS(ctx, &job, d); err != nil {
			return s.fail(&job, err)
		}
	} else {
		node, err := certificateNode(ctx, job.NodeID)
		if err != nil {
			return s.fail(&job, err)
		}
		d.node = node
		var ids []string
		_ = json.Unmarshal([]byte(job.RecordIDs), &ids)
		validated, err := s.validateRecords(ctx, d, ids, job.PrimaryDomain)
		if err != nil {
			return s.fail(&job, err)
		}
		if strings.Join(validated, "\n") != strings.Join(domains, "\n") {
			return s.fail(&job, pairingError(409, "certificate_dns_record_changed"))
		}
	}
	var bundle panelcert.Bundle
	if job.Payload != "" {
		if job.ExpiresAt <= time.Now().Add(time.Hour).UnixMilli() && job.NodeID > 0 {
			replacement := model.NodeCertificateJob{ID: uuid.NewString(), NodeID: job.NodeID, NodeGUID: job.NodeGUID, ActiveSlot: &job.NodeGUID, ZoneID: job.ZoneID, Domains: job.Domains, RecordIDs: job.RecordIDs, PrimaryDomain: job.PrimaryDomain, Status: "queued"}
			return pairingDB().Transaction(func(tx *gorm.DB) error {
				if err := tx.Model(&job).Updates(map[string]any{"status": "superseded", "active_slot": nil, "payload": "", "acme_state": ""}).Error; err != nil {
					return err
				}
				return tx.Create(&replacement).Error
			})
		}
		bundle, err = openCertificateBundle(&job)
		if err != nil {
			return s.fail(&job, errors.New("certificate_key_unavailable"))
		}
		if _, err = bundle.Validate(time.Now(), s.roots); err != nil {
			return s.fail(&job, err)
		}
	} else {
		_ = pairingDB().Model(&job).Update("status", "issuing").Error
		bundle, err = s.issue(ctx, &job, d, domains)
		if err != nil {
			return s.fail(&job, err)
		}
		pair, err := bundle.Validate(time.Now(), s.roots)
		if err != nil {
			return s.fail(&job, err)
		}
		if strings.Join(bundle.Domains, "\n") != strings.Join(domains, "\n") {
			return s.fail(&job, errors.New("invalid_panel_certificate"))
		}
		job.Payload, err = sealCertificateBundle(job.ID, bundle)
		if err != nil {
			return s.fail(&job, err)
		}
		job.Fingerprint = panelcert.Fingerprint(pair.Leaf)
		job.ExpiresAt = pair.Leaf.NotAfter.UnixMilli()
		if err := pairingDB().Model(&job).Updates(map[string]any{"payload": job.Payload, "fingerprint": job.Fingerprint, "expires_at": job.ExpiresAt, "status": "deploying", "acme_state": ""}).Error; err != nil {
			return err
		}
	}
	if job.NodeID > 0 {
		var ids []string
		_ = json.Unmarshal([]byte(job.RecordIDs), &ids)
		validated, err := s.validateRecords(ctx, d, ids, job.PrimaryDomain)
		if err != nil {
			return s.fail(&job, err)
		}
		if strings.Join(validated, "\n") != strings.Join(domains, "\n") {
			return s.fail(&job, pairingError(409, "certificate_dns_record_changed"))
		}
	}
	if err := pairingDB().Model(&job).Updates(map[string]any{"status": "deploying", "last_error": ""}).Error; err != nil {
		return err
	}
	if staged, err := stageMigrationCertificate(ctx, &job); staged || err != nil {
		if err != nil {
			return s.fail(&job, err)
		}
		return nil
	}
	if err := s.deployBundle(ctx, &job, bundle); err != nil {
		return s.fail(&job, err)
	}
	return pairingDB().Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.NodeCertificateJob{}).Where("node_guid = ? AND id <> ? AND active = ?", job.NodeGUID, job.ID, true).Updates(map[string]any{"active": false, "payload": ""}).Error; err != nil {
			return err
		}
		return tx.Model(&job).Updates(map[string]any{"status": "active", "active": true, "active_slot": nil, "last_error": "", "next_attempt_at": 0}).Error
	})
}

func (s *NodeCertificateService) fail(job *model.NodeCertificateJob, failure error) error {
	attempts := job.Attempts + 1
	delay := time.Minute * time.Duration(1<<min(attempts-1, 6))
	if delay > time.Hour {
		delay = time.Hour
	}
	if err := pairingDB().Model(job).Updates(map[string]any{"status": "retrying", "last_error": certificateFailureCode(failure), "attempts": attempts, "next_attempt_at": time.Now().Add(delay).UnixMilli()}).Error; err != nil {
		return err
	}
	return failure
}

func (s *NodeCertificateService) renew(ctx context.Context, now time.Time) error {
	certificateJobMu.Lock()
	defer certificateJobMu.Unlock()
	var active []model.NodeCertificateJob
	if err := pairingDB().WithContext(ctx).Where("active = ? AND node_id > 0 AND expires_at <= ?", true, now.Add(30*24*time.Hour).UnixMilli()).Find(&active).Error; err != nil {
		return err
	}
	for _, old := range active {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		node, err := certificateNode(ctx, old.NodeID)
		if err != nil || node.Guid != old.NodeGUID {
			continue
		}
		var count int64
		if err := pairingDB().Model(&model.NodeCertificateJob{}).Where("active_slot = ?", old.NodeGUID).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			continue
		}
		// Short-lived certificates cannot wait for a fixed 30-day boundary.
		// Avoid repeated orders immediately after a successful issuance.
		renewAt := max(old.ExpiresAt-30*24*time.Hour.Milliseconds(), old.CreatedAt+(old.ExpiresAt-old.CreatedAt)*2/3)
		if now.UnixMilli() < renewAt {
			continue
		}
		job := model.NodeCertificateJob{ID: uuid.NewString(), NodeID: old.NodeID, NodeGUID: old.NodeGUID, ActiveSlot: &old.NodeGUID, ZoneID: old.ZoneID, Domains: old.Domains, RecordIDs: old.RecordIDs, PrimaryDomain: old.PrimaryDomain, Status: "queued"}
		if err := pairingDB().Create(&job).Error; err != nil {
			return err
		}
	}
	return nil
}

func RunCertificateWorker(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	leaseDone := make(chan struct{})
	go func() {
		defer close(leaseDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			recoverCertificateInstall(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		defer close(done)
		defer func() { <-leaseDone }()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var checked time.Time
		s := &NodeCertificateService{}
		for ctx.Err() == nil {
			if role, err := (&SettingService{}).GetPanelRole(); err == nil && role == PanelRoleMaster {
				_ = expireCertificateEnrollments(time.Now())
				if checked.IsZero() || time.Since(checked) >= 12*time.Hour {
					if err := s.renew(ctx, time.Now()); err == nil {
						checked = time.Now()
					}
				}
				var jobs []model.NodeCertificateJob
				if err := pairingDB().Where("active_slot IS NOT NULL AND next_attempt_at <= ?", time.Now().UnixMilli()).Order("created_at ASC").Find(&jobs).Error; err == nil {
					for _, job := range jobs {
						if ctx.Err() != nil {
							return
						}
						cycle, cancel := context.WithTimeout(ctx, 10*time.Minute)
						_ = s.step(cycle, job.ID)
						cancel()
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-certificateWake:
			}
		}
	}()
	return done
}
