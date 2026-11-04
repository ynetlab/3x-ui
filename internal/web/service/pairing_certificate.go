package service

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/mhsanaei/3x-ui/v3/internal/cloudflare"
	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/crypto/nodetoken"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/nodeip"
)

func enrollmentRegistration(row *model.NodeEnrollment) (cluster.RegisterRequest, error) {
	var req cluster.RegisterRequest
	if nodetoken.IsEncrypted(row.Registration) && !nodetoken.Enabled() {
		return req, pairingError(503, "certificate_key_unavailable")
	}
	data, err := nodetoken.DecryptBound([]byte("enrollment-registration/"+row.ID), row.Registration)
	if err != nil {
		return req, err
	}
	err = json.Unmarshal([]byte(data), &req)
	return req, err
}

func (s *NodeCertificateService) prepareEnrollmentCertificate(ctx context.Context, row *model.NodeEnrollment, req cluster.RegisterRequest) (bool, error) {
	certificateJobMu.Lock()
	defer certificateJobMu.Unlock()
	id := uuid.NewSHA1(uuid.NameSpaceURL, []byte("panel-certificate/"+row.ID)).String()
	var job model.NodeCertificateJob
	err := pairingDB().Where("id = ?", id).First(&job).Error
	if err == nil {
		original, err := enrollmentRegistration(row)
		if err != nil {
			return false, err
		}
		before, _ := json.Marshal(original)
		after, _ := json.Marshal(req)
		if string(before) != string(after) {
			return false, pairingError(409, "registration_payload_changed")
		}
		return job.Active && job.Status == "active" || row.ExistingNodeID != 0 && job.Status == "staged", nil
	}
	if !database.IsNotFound(err) {
		return false, err
	}
	if req.PublicIP == nil || req.PublicIP.IPv4 == "" && req.PublicIP.IPv6 == "" || req.PanelPort < 1 || req.PanelPort > 65535 || req.PublicIP.ObservedAt <= 0 || req.PublicIP.ObservedAt < row.CreatedAt-5*time.Minute.Milliseconds() || req.PublicIP.ObservedAt > time.Now().Add(5*time.Minute).UnixMilli() {
		return false, pairingError(503, "pairing_public_ip_unavailable")
	}
	for _, family := range []struct {
		value string
		v4    bool
	}{{req.PublicIP.IPv4, true}, {req.PublicIP.IPv6, false}} {
		if family.value != "" {
			if _, err := nodeip.PublicIP(family.value, family.v4); err != nil {
				return false, pairingError(400, "invalid_node_ip_report")
			}
		}
	}
	data, _ := json.Marshal(req)
	registration, err := nodetoken.EncryptBound([]byte("enrollment-registration/"+row.ID), string(data))
	if err != nil {
		return false, err
	}
	job = model.NodeCertificateJob{ID: id, NodeGUID: row.SlaveGUID, EnrollmentID: row.ID, ActiveSlot: &row.SlaveGUID, ZoneID: row.ZoneID, Domains: row.Domains, PrimaryDomain: row.PrimaryDomain, RecordIDs: "[]", Status: "queued"}
	if err := pairingDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&job).Error; err != nil {
			return err
		}
		return tx.Model(row).Updates(map[string]any{"registration": registration, "status": PairingProvisioning}).Error
	}); err != nil {
		return false, err
	}
	wakeCertificateWorker()
	return false, nil
}

func (s *NodeCertificateService) enrollmentTarget(ctx context.Context, job *model.NodeCertificateJob) (certificateTarget, error) {
	row, err := (&PairingService{}).enrollment(job.EnrollmentID)
	if err != nil {
		return certificateTarget{}, err
	}
	if row.SlaveGUID != job.NodeGUID || enrollmentView(row).Status == PairingExpired || row.Status != PairingProvisioning && row.Status != PairingVerifying && row.Status != PairingIssued {
		return certificateTarget{}, pairingError(410, "enrollment_expired")
	}
	if row.ExistingNodeID != 0 {
		if _, err := checkMigrationNode(pairingDB(), row); err != nil {
			return certificateTarget{}, err
		}
	}
	req, err := enrollmentRegistration(row)
	if err != nil {
		return certificateTarget{}, err
	}
	credentials, err := (&SettingService{}).EnsureControlCredentials()
	if err != nil {
		return certificateTarget{}, err
	}
	peer, err := cluster.PeerFromPEM(row.CertPEM)
	if err != nil {
		return certificateTarget{}, err
	}
	config, err := cluster.ClientTLS(credentials, peer)
	if err != nil {
		return certificateTarget{}, err
	}
	config.NextProtos = []string{cluster.PairingALPN, "http/1.1"}
	return certificateTarget{address: req.Address, port: req.Port, token: req.AdminToken, allowPrivate: row.AllowPrivateAddress, tls: config, enrollment: row.ID, deferConfirm: row.ExistingNodeID != 0}, nil
}

// dnsBindingOwnerLive includes not-yet-published enrollment owners. Their
// bindings must not be reclaimed as if they belonged to a deleted Node.
func dnsBindingOwnerLive(tx *gorm.DB, b model.NodeDNSBinding) (bool, error) {
	var count int64
	if err := tx.Model(&model.Node{}).Where("id = ? AND guid = ?", b.NodeID, b.NodeGUID).Count(&count).Error; err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}
	var enrollments []model.NodeEnrollment
	if err := tx.Where("slave_guid = ? AND status IN ?", b.NodeGUID, []string{PairingIssued, PairingVerifying, PairingProvisioning}).Find(&enrollments).Error; err != nil {
		return false, err
	}
	for _, row := range enrollments {
		if enrollmentView(&row).Status != PairingExpired {
			return true, nil
		}
	}
	return false, nil
}

func (s *NodeCertificateService) provisionEnrollmentDNS(ctx context.Context, job *model.NodeCertificateJob, d *dnsSession) error {
	if err := lockCloudflareDNS(ctx); err != nil {
		return err
	}
	defer func() { <-cloudflareDNSGate }()
	row, err := (&PairingService{}).enrollment(job.EnrollmentID)
	if err != nil {
		return err
	}
	if row.SlaveGUID != job.NodeGUID || enrollmentView(row).Status == PairingExpired {
		return pairingError(410, "enrollment_expired")
	}
	req, err := enrollmentRegistration(row)
	if err != nil || req.PublicIP == nil {
		return pairingError(409, "invalid_node_ip_report")
	}
	var domains []string
	_ = json.Unmarshal([]byte(job.Domains), &domains)
	ids := []string{}
	for _, name := range domains {
		for _, address := range []struct{ kind, ip string }{{"A", req.PublicIP.IPv4}, {"AAAA", req.PublicIP.IPv6}} {
			if address.ip == "" {
				continue
			}
			records, err := d.find(ctx, url.Values{"type": {address.kind}, "name.exact": {name}})
			if err != nil {
				return err
			}
			var record cloudflare.Record
			for _, candidate := range records {
				if candidate.Name != name || candidate.Type != address.kind {
					continue
				}
				if record.ID != "" || candidate.Content != address.ip || candidate.Proxied {
					return pairingError(409, "certificate_dns_conflict")
				}
				record = candidate
			}
			if record.ID == "" {
				record, err = d.client.Create(ctx, d.zone.ID, map[string]any{"type": address.kind, "name": name, "content": address.ip, "ttl": 1, "proxied": false})
				if err != nil {
					return err
				}
			}
			if record.Name != name || record.Type != address.kind || record.Content != address.ip || record.Proxied {
				return pairingError(502, "cloudflare_invalid_response")
			}
			if err := pairingDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				var existing model.NodeDNSBinding
				err := tx.Where("zone_id = ? AND record_id = ?", d.zone.ID, record.ID).First(&existing).Error
				if err != nil && !database.IsNotFound(err) {
					return err
				}
				if err == nil && existing.NodeGUID != job.NodeGUID {
					live, err := dnsBindingOwnerLive(tx, existing)
					if err != nil {
						return err
					}
					if live {
						return pairingError(409, "cloudflare_record_owned_by_other_node")
					}
				}
				binding := model.NodeDNSBinding{NodeGUID: job.NodeGUID, ZoneID: d.zone.ID, RecordID: record.ID, Name: record.Name, Type: record.Type, Content: record.Content, TTL: record.TTL, Proxied: false}
				return tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "zone_id"}, {Name: "record_id"}}, DoUpdates: clause.Assignments(map[string]any{"node_id": 0, "node_guid": job.NodeGUID, "name": record.Name, "type": record.Type, "content": record.Content, "ttl": record.TTL, "proxied": false})}).Create(&binding).Error
			}); err != nil {
				return err
			}
			ids = append(ids, record.ID)
		}
	}
	idData, _ := json.Marshal(ids)
	job.RecordIDs = string(idData)
	return pairingDB().Model(job).Update("record_ids", job.RecordIDs).Error
}

func attachEnrollmentCertificate(tx *gorm.DB, row *model.NodeEnrollment, node *model.Node, req cluster.RegisterRequest) error {
	if req.PublicIP == nil {
		return pairingError(503, "pairing_public_ip_unavailable")
	}
	var job model.NodeCertificateJob
	if err := tx.Where("enrollment_id = ? AND node_guid = ?", row.ID, node.Guid).First(&job).Error; err != nil {
		return err
	}
	if row.ExistingNodeID == 0 && (!job.Active || job.Status != "active") || row.ExistingNodeID != 0 && job.Status != "staged" {
		return pairingError(503, "migration_certificate_pending")
	}
	if job.PrimaryDomain != node.Address {
		return pairingError(409, "certificate_primary_domain_changed")
	}
	if err := tx.Model(&job).Updates(map[string]any{"node_id": node.Id, "next_attempt_at": 0}).Error; err != nil {
		return err
	}
	if err := tx.Model(&model.NodeDNSBinding{}).Where("node_id = 0 AND node_guid = ? AND zone_id = ?", node.Guid, job.ZoneID).Update("node_id", node.Id).Error; err != nil {
		return err
	}
	ip := model.NodePublicIP{NodeID: node.Id, NodeGUID: node.Guid, IPv4: strings.TrimSpace(req.PublicIP.IPv4), IPv6: strings.TrimSpace(req.PublicIP.IPv6), IPv4Available: req.PublicIP.IPv4 != "", IPv6Available: req.PublicIP.IPv6 != "", ObservedAt: req.PublicIP.ObservedAt, ReceivedAt: time.Now().UnixMilli()}
	return tx.Create(&ip).Error
}

func expireCertificateEnrollments(now time.Time) error {
	enrollmentMu.Lock()
	defer enrollmentMu.Unlock()
	return pairingDB().Model(&model.NodeEnrollment{}).Where("status IN ? AND resume_until <= ?", []string{PairingIssued, PairingVerifying, PairingProvisioning}, now.UnixMilli()).Updates(map[string]any{"status": PairingExpired, "active_name": nil, "active_guid": nil, "active_node_id": nil, "registration": ""}).Error
}
