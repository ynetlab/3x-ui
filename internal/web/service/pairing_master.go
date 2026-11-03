package service

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/crypto/nodetoken"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/netsafe"
	"github.com/mhsanaei/3x-ui/v3/internal/web/runtime"
	"gorm.io/gorm"
)

type CreateEnrollmentRequest struct {
	Name                string   `json:"name"`
	MasterAddress       string   `json:"masterAddress"`
	AllowPrivateAddress bool     `json:"allowPrivateAddress"`
	Domains             []string `json:"domains"`
	PrimaryDomain       string   `json:"primaryDomain"`
	ExistingNodeID      int      `json:"existingNodeId,omitempty"`
	Recovery            bool     `json:"recovery,omitempty"`
}

type CreatedEnrollment struct {
	PairingView
	Profile cluster.PairingProfile `json:"profile"`
}

func (s *PairingService) CreateEnrollment(req CreateEnrollmentRequest) (CreatedEnrollment, error) {
	if req.Recovery {
		return s.createRecoveryEnrollment(req)
	}
	settings := &SettingService{}
	self, err := settings.ControlIdentity()
	if err != nil {
		return CreatedEnrollment{}, err
	}
	if self.Role != cluster.RoleMaster {
		return CreatedEnrollment{}, pairingError(403, "only_master_can_enroll_nodes")
	}
	var existing *model.Node
	if req.ExistingNodeID != 0 {
		existing, err = migrationNode(context.Background(), req.ExistingNodeID)
		if err != nil {
			return CreatedEnrollment{}, err
		}
		if req.Name != "" && strings.TrimSpace(req.Name) != existing.Name {
			return CreatedEnrollment{}, pairingError(409, "migration_node_changed")
		}
		req.Name = existing.Name
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || existing == nil && len(req.Name) > 256 {
		return CreatedEnrollment{}, pairingError(400, "invalid_node_name")
	}
	if len(req.Domains) == 0 || strings.TrimSpace(req.PrimaryDomain) == "" {
		return CreatedEnrollment{}, pairingError(400, "invalid_certificate_domains")
	}
	certificates := s.certificates
	if certificates == nil {
		certificates = &NodeCertificateService{}
	}
	acmeConfig, err := certificates.Config()
	if err != nil {
		return CreatedEnrollment{}, err
	}
	if acmeConfig.Email == "" || !acmeConfig.AcceptTOS {
		return CreatedEnrollment{}, pairingError(409, "acme_not_configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	d, err := certificates.configuredDNS(ctx)
	cancel()
	if err != nil {
		return CreatedEnrollment{}, err
	}
	domains, primary, err := certificateDomains(req.Domains, req.PrimaryDomain, d.zone.Name)
	if err != nil {
		return CreatedEnrollment{}, err
	}
	data, _ := json.Marshal(domains)
	domainData, zoneID := string(data), d.zone.ID
	req.PrimaryDomain = primary
	address, err := netsafe.NormalizeHost(req.MasterAddress)
	if err != nil {
		return CreatedEnrollment{}, pairingError(400, "invalid_master_address")
	}
	config, err := settings.GetControlConfig()
	if err != nil {
		return CreatedEnrollment{}, err
	}
	if !config.Enabled {
		return CreatedEnrollment{}, pairingError(409, "control_listener_disabled")
	}
	enrollmentMu.Lock()
	defer enrollmentMu.Unlock()
	credentials, err := settings.EnsureControlCredentials()
	if err != nil {
		return CreatedEnrollment{}, err
	}
	peer, err := controlPeer(credentials)
	if err != nil {
		return CreatedEnrollment{}, err
	}
	token, err := randomPairingSecret()
	if err != nil {
		return CreatedEnrollment{}, err
	}
	now := time.Now().UnixMilli()
	db := pairingDB()
	// Release expired reservations, keeping the history and consumed token hash.
	if err := db.Model(&model.NodeEnrollment{}).Where("(status = ? AND expires_at <= ?) OR (status IN ? AND resume_until <= ?)", PairingPending, now, []string{PairingIssued, PairingVerifying, PairingProvisioning}, now).
		Updates(map[string]any{"status": PairingExpired, "active_name": nil, "active_guid": nil, "active_node_id": nil, "registration": ""}).Error; err != nil {
		return CreatedEnrollment{}, err
	}
	var count int64
	if err := db.Model(&model.Node{}).Where("name = ? AND id <> ?", req.Name, req.ExistingNodeID).Count(&count).Error; err != nil {
		return CreatedEnrollment{}, err
	}
	if count != 0 {
		return CreatedEnrollment{}, pairingError(409, "node_name_already_exists")
	}
	row := model.NodeEnrollment{ID: uuid.NewString(), Name: req.Name, ActiveName: &req.Name,
		TokenHash: pairingHash(token), Status: PairingPending, ExpiresAt: now + cluster.EnrollmentTTL.Milliseconds(), AllowPrivateAddress: req.AllowPrivateAddress, Domains: domainData, PrimaryDomain: req.PrimaryDomain, ZoneID: zoneID}
	if existing != nil {
		// The old Node already owns its unique name. Reserve its ID instead,
		// without applying the new-enrollment name limit to existing data.
		row.ActiveName = nil
		row.ExistingNodeID, row.ActiveNodeID = existing.Id, &existing.Id
		row.ExpectedGUID, row.MigrationSnapshot = existing.Guid, migrationSnapshot(existing)
		row.OriginalEnable = existing.Enable
	}
	if err := db.Create(&row).Error; err != nil {
		if existing != nil {
			return CreatedEnrollment{}, pairingError(409, "migration_already_pending")
		}
		return CreatedEnrollment{}, pairingError(409, "enrollment_name_reserved")
	}
	return CreatedEnrollment{PairingView: enrollmentView(&row), Profile: cluster.PairingProfile{EnrollmentID: row.ID,
		MasterAddress: address, MasterPort: config.Port, Master: peer, Token: token, ExpiresAt: row.ExpiresAt}}, nil
}

func (s *PairingService) VerifyEnrollmentToken(ctx context.Context, token string) error {
	var row model.NodeEnrollment
	if err := pairingDB().WithContext(ctx).Where("token_hash = ?", pairingHash(token)).First(&row).Error; err != nil {
		return pairingError(401, "invalid_enrollment_token")
	}
	if enrollmentView(&row).Status == PairingExpired || row.Status == PairingFailed || row.Status != PairingPending && time.Now().UnixMilli() >= row.ResumeUntil {
		return pairingError(401, "enrollment_expired")
	}
	return nil
}

func (s *PairingService) Enroll(token string, req cluster.EnrollRequest) (cluster.EnrollResponse, error) {
	if !validPairingID(req.EnrollmentID) || !validPairingID(req.GUID) {
		return cluster.EnrollResponse{}, pairingError(400, "invalid_enrollment_identity")
	}
	enrollmentMu.Lock()
	defer enrollmentMu.Unlock()
	row, err := s.enrollment(req.EnrollmentID)
	if err != nil {
		return cluster.EnrollResponse{}, pairingError(401, "invalid_enrollment_token")
	}
	if row.TokenHash != pairingHash(token) {
		return cluster.EnrollResponse{}, pairingError(401, "invalid_enrollment_token")
	}
	if enrollmentView(row).Status == PairingExpired || row.Status == PairingFailed || row.Status != PairingPending && time.Now().UnixMilli() >= row.ResumeUntil {
		return cluster.EnrollResponse{}, pairingError(410, "enrollment_expired")
	}
	settings := &SettingService{}
	credentials, err := settings.EnsureControlCredentials()
	if err != nil {
		return cluster.EnrollResponse{}, err
	}
	master, err := controlPeer(credentials)
	if err != nil {
		return cluster.EnrollResponse{}, err
	}
	if master.GUID == req.GUID {
		return cluster.EnrollResponse{}, pairingError(409, "cannot_pair_node_with_itself")
	}
	csrHash := pairingHash(req.CSR)
	if row.Recovery {
		if err := verifyRecoveryEnrollment(row, req, master, credentials.CACertPEM); err != nil {
			return cluster.EnrollResponse{}, err
		}
	}
	if row.ExistingNodeID != 0 {
		if req.GUID != row.ExpectedGUID {
			return cluster.EnrollResponse{}, pairingError(409, "migration_node_identity_mismatch")
		}
		if row.Status != PairingRegistered && row.Status != PairingCompleted {
			if _, err := checkMigrationNode(pairingDB(), row); err != nil {
				return cluster.EnrollResponse{}, err
			}
		}
	}
	if row.Status != PairingPending {
		if row.SlaveGUID != req.GUID || row.CSRHash != csrHash {
			return cluster.EnrollResponse{}, pairingError(409, "enrollment_token_already_claimed")
		}
		return cluster.EnrollResponse{CertPEM: row.CertPEM, CACertPEM: credentials.CACertPEM, Master: master, ResumeUntil: row.ResumeUntil}, nil
	}
	var count int64
	if err := pairingDB().Model(&model.Node{}).Where("guid = ? AND id <> ?", req.GUID, row.ExistingNodeID).Count(&count).Error; err != nil {
		return cluster.EnrollResponse{}, err
	}
	if count != 0 {
		return cluster.EnrollResponse{}, pairingError(409, "node_guid_already_registered")
	}
	cert, ca, err := settings.IssueControlIdentity([]byte(req.CSR), cluster.Identity{GUID: req.GUID, Role: cluster.RoleSlave})
	if err != nil {
		return cluster.EnrollResponse{}, pairingError(400, "invalid_enrollment_csr")
	}
	until := time.Now().Add(cluster.EnrollmentResumeTTL).UnixMilli()
	result := pairingDB().Model(&model.NodeEnrollment{}).Where("id = ? AND status = ?", row.ID, PairingPending).
		Updates(map[string]any{"status": PairingIssued, "slave_guid": req.GUID, "active_guid": req.GUID, "csr_hash": csrHash, "cert_pem": string(cert), "resume_until": until})
	if result.Error != nil || result.RowsAffected != 1 {
		return cluster.EnrollResponse{}, pairingError(409, "enrollment_claim_conflict")
	}
	return cluster.EnrollResponse{CertPEM: string(cert), CACertPEM: ca, Master: master, ResumeUntil: until}, nil
}

func (s *PairingService) EnrollmentPeer(ctx context.Context, id, guid string) (cluster.Peer, error) {
	row, err := s.enrollment(id)
	if err != nil {
		return cluster.Peer{}, err
	}
	if row.SlaveGUID != guid || row.Status == PairingPending || row.Status == PairingFailed || enrollmentView(row).Status == PairingExpired {
		return cluster.Peer{}, cluster.ErrPeerNotTrusted
	}
	// Committed enrollments respect revocation and node deletion, too.
	if row.Status == PairingRegistered || row.Status == PairingCompleted {
		var count int64
		if err := pairingDB().Model(&model.Node{}).Where("id = ? AND guid = ?", row.NodeID, guid).Count(&count).Error; err != nil || count != 1 {
			return cluster.Peer{}, cluster.ErrPeerNotTrusted
		}
		return (&SettingService{}).LookupControlPeer(ctx, guid)
	}
	// Only the public leaf is needed to bind incoming client identity.
	return cluster.PeerFromPEM(row.CertPEM)
}

func (s *PairingService) Register(ctx context.Context, id string, req cluster.RegisterRequest) (receipt cluster.PairingReceipt, failure error) {
	// Serialize claims/registration, but never keep a database transaction open
	// during a callback. Request timeouts can safely replay the same payload.
	enrollmentMu.Lock()
	defer enrollmentMu.Unlock()
	row, err := s.enrollment(id)
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	if row.ExistingNodeID != 0 && row.Status != PairingRegistered && row.Status != PairingCompleted {
		defer func() {
			if failure != nil {
				_ = pairingDB().Model(row).Update("last_error", pairingFailureCode(failure)).Error
			}
		}()
	}
	if enrollmentView(row).Status == PairingExpired {
		return cluster.PairingReceipt{}, pairingError(410, "enrollment_expired")
	}
	address, err := netsafe.NormalizeHost(req.Address)
	if err != nil || req.Port < 1 || req.Port > 65535 || len(req.AdminToken) < 16 || len(req.AdminToken) > 512 {
		return cluster.PairingReceipt{}, pairingError(400, "invalid_node_registration")
	}
	basePath, err := normalizedPairingPath(req.BasePath)
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	adminHash := pairingHash(req.AdminToken)
	if row.Status == PairingRegistered || row.Status == PairingCompleted {
		if row.Address != address || row.Port != req.Port || row.BasePath != basePath || row.AdminHash != adminHash {
			return cluster.PairingReceipt{}, pairingError(409, "registration_payload_changed")
		}
		return cluster.PairingReceipt{NodeID: row.NodeID, Status: row.Status}, nil
	}
	if row.Status != PairingIssued && row.Status != PairingVerifying && row.Status != PairingProvisioning {
		return cluster.PairingReceipt{}, pairingError(409, "enrollment_not_issued")
	}
	if row.ExistingNodeID != 0 {
		if _, err := checkMigrationNode(pairingDB(), row); err != nil {
			return cluster.PairingReceipt{}, err
		}
	}
	phase := PairingVerifying
	if row.Registration != "" {
		phase = PairingProvisioning
	}
	if err := pairingDB().Model(row).Updates(map[string]any{"status": phase, "last_error": ""}).Error; err != nil {
		return cluster.PairingReceipt{}, err
	}
	settings := &SettingService{}
	credentials, err := settings.EnsureControlCredentials()
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	peer, err := cluster.PeerFromPEM(row.CertPEM)
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	cfg, err := cluster.ClientTLS(credentials, peer)
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	cfg.NextProtos = []string{cluster.PairingALPN, "http/1.1"}
	challenge, err := randomPairingSecret()
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	var response cluster.ProbeResponse
	err = pairingRPC(ctx, cfg, row.AllowPrivateAddress, pairingURL(address, req.Port, cluster.PairingProbePath), req.AdminToken,
		cluster.ProbeRequest{EnrollmentID: id, Challenge: challenge}, &response)
	if err == nil && (response.GUID != row.SlaveGUID || response.Challenge != challenge || response.Role != cluster.RoleSlave) {
		err = pairingError(502, "pairing_probe_identity_mismatch")
	}
	if err != nil {
		_ = pairingDB().Model(row).Updates(map[string]any{"status": PairingIssued, "last_error": pairingFailureCode(err)}).Error
		return cluster.PairingReceipt{}, err
	}
	if time.Now().UnixMilli() >= row.ResumeUntil {
		return cluster.PairingReceipt{}, pairingError(410, "enrollment_expired")
	}
	registrationAddress := address
	if row.Recovery {
		return registerRecoveryNode(row, req, peer, registrationAddress, basePath)
	}
	ready, err := (&NodeCertificateService{}).prepareEnrollmentCertificate(ctx, row, req)
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	if !ready {
		return cluster.PairingReceipt{Status: PairingProvisioning}, nil
	}
	if row.ExistingNodeID != 0 {
		// Serialize staging and cutover without waiting behind another node's
		// potentially slow ACME order inside a five-second registration request.
		if !certificateStepMu.TryLock() {
			return cluster.PairingReceipt{Status: PairingProvisioning}, nil
		}
		defer certificateStepMu.Unlock()
	}
	rollbackMigration, err := activateMigrationCertificate(ctx, row, s.certificates)
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	committed := false
	defer func() {
		if !committed && rollbackMigration != nil {
			rollbackMigration()
		}
	}()
	address = row.PrimaryDomain
	// Resolve and authenticate the domain before publishing it as the Node
	// address. Certificate delivery alone does not prove DNS propagation.
	var domainResponse cluster.ProbeResponse
	if err := pairingRPC(ctx, cfg, row.AllowPrivateAddress, pairingURL(address, req.Port, cluster.PairingProbePath), req.AdminToken, cluster.ProbeRequest{EnrollmentID: id, Challenge: challenge}, &domainResponse); err != nil {
		return cluster.PairingReceipt{}, pairingError(503, "pairing_domain_callback_failed")
	}
	if domainResponse.GUID != row.SlaveGUID || domainResponse.Challenge != challenge || domainResponse.Role != cluster.RoleSlave {
		return cluster.PairingReceipt{}, pairingError(502, "pairing_probe_identity_mismatch")
	}
	node := &model.Node{Name: row.Name, Scheme: "https", Address: address, Port: req.Port, BasePath: basePath,
		ApiToken: req.AdminToken, Guid: row.SlaveGUID, TlsVerifyMode: "mtls", PinnedCertSha256: peer.Fingerprint,
		ControlConnection: true, AllowPrivateAddress: row.AllowPrivateAddress, InboundSyncMode: "all"}
	service := &NodeService{}
	if err := service.normalize(node); err != nil {
		return cluster.PairingReceipt{}, err
	}
	controlSettingsMu.Lock()
	defer controlSettingsMu.Unlock()
	if time.Now().UnixMilli() >= row.ResumeUntil {
		return cluster.PairingReceipt{}, pairingError(410, "enrollment_expired")
	}
	err = pairingDB().Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&model.Node{}).Where("(guid = ? OR name = ?) AND id <> ?", row.SlaveGUID, row.Name, row.ExistingNodeID).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return pairingError(409, "node_already_registered")
		}
		if row.ExistingNodeID != 0 {
			if err := commitMigrationNode(tx, row, node); err != nil {
				return err
			}
		} else {
			if err := service.createTx(tx, node); err != nil {
				return err
			}
		}
		// GORM applies default:true on creation. Keep the node disabled until
		// the source commits slave mode and acknowledges the registration.
		if err := tx.Model(node).Update("enable", false).Error; err != nil {
			return err
		}
		ownPeer, err := controlPeer(credentials)
		if err != nil {
			return err
		}
		peer.AcknowledgedLocalFingerprint = ownPeer.Fingerprint
		if err := trustPairingPeer(tx, peer); err != nil {
			return err
		}
		if err := attachEnrollmentCertificate(tx, row, node, req); err != nil {
			return err
		}
		return tx.Model(row).Updates(map[string]any{"status": PairingRegistered, "node_id": node.Id, "address": registrationAddress,
			"port": req.Port, "base_path": basePath, "admin_hash": adminHash, "last_error": "", "registration": ""}).Error
	})
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	committed = true
	runtime.InvalidateMasterClientConnections()
	if manager := runtime.GetManager(); manager != nil {
		manager.InvalidateNode(node.Id)
	}
	return cluster.PairingReceipt{NodeID: node.Id, Status: PairingRegistered}, nil
}

func (s *PairingService) Complete(ctx context.Context, id string) (cluster.PairingReceipt, error) {
	enrollmentMu.Lock()
	defer enrollmentMu.Unlock()
	row, err := s.enrollment(id)
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	if row.Status != PairingRegistered && row.Status != PairingCompleted {
		return cluster.PairingReceipt{}, pairingError(409, "node_not_registered")
	}
	var node model.Node
	if err := pairingDB().Where("id = ? AND guid = ?", row.NodeID, row.SlaveGUID).First(&node).Error; err != nil {
		return cluster.PairingReceipt{}, pairingError(410, "paired_node_removed")
	}
	if row.Status == PairingCompleted {
		return cluster.PairingReceipt{NodeID: node.Id, Status: PairingCompleted}, nil
	}
	if row.ExistingNodeID != 0 && !row.Recovery {
		var active int64
		if err := pairingDB().Model(&model.NodeCertificateJob{}).Where("enrollment_id = ? AND node_id = ? AND active = ?", row.ID, node.Id, true).Count(&active).Error; err != nil {
			return cluster.PairingReceipt{}, err
		}
		if active != 1 {
			return cluster.PairingReceipt{}, pairingError(503, "migration_certificate_pending")
		}
	}
	credentials, err := (&SettingService{}).EnsureControlCredentials()
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	peer, err := (&SettingService{}).LookupControlPeer(ctx, row.SlaveGUID)
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	cfg, err := cluster.ClientTLS(credentials, peer)
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	token, err := nodetoken.Decrypt(node.Id, node.ApiToken)
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	// This is the existing full-admin management API, now reached without
	// the staged TLS marker, proving that active slave mode is usable.
	var result struct {
		Success bool `json:"success"`
	}
	if err := pairingRPC(ctx, cfg, node.AllowPrivateAddress, pairingURL(node.Address, node.Port, node.BasePath+"panel/api/setting/all"), token, struct{}{}, &result); err != nil {
		return cluster.PairingReceipt{}, err
	}
	if !result.Success {
		return cluster.PairingReceipt{}, pairingError(502, "paired_node_management_not_ready")
	}
	err = pairingDB().Transaction(func(tx *gorm.DB) error {
		enabled := row.ExistingNodeID == 0 || row.OriginalEnable
		if err := tx.Model(&node).Updates(map[string]any{"enable": enabled, "control_recovery_enable": false}).Error; err != nil {
			return err
		}
		return tx.Model(row).Updates(map[string]any{"status": PairingCompleted, "active_name": nil, "active_guid": nil, "active_node_id": nil, "last_error": "", "registration": ""}).Error
	})
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	if manager := runtime.GetManager(); manager != nil {
		manager.InvalidateNode(node.Id)
	}
	return cluster.PairingReceipt{NodeID: node.Id, Status: PairingCompleted}, nil
}
