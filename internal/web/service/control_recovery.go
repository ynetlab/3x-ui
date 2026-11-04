package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/netsafe"
)

func normalizeRecoveryMaster(value string) (string, error) {
	address, err := netsafe.NormalizeHost(value)
	if err != nil {
		return "", pairingError(400, "invalid_master_address")
	}
	return address, nil
}

func verifyRecoveryEnrollment(row *model.NodeEnrollment, req cluster.EnrollRequest, master cluster.Peer, ca string) error {
	var node model.Node
	if err := pairingDB().First(&node, row.ExistingNodeID).Error; err != nil {
		return err
	}
	message := cluster.RecoveryMessage(row.ID, req.GUID, req.CSR, master.Fingerprint)
	expected := cluster.Identity{GUID: row.ExpectedGUID, Role: cluster.RoleSlave}
	if node.Guid != row.ExpectedGUID {
		return pairingError(409, "migration_node_changed")
	}
	if cluster.VerifyRecoveryProof(req.RecoveryCert, row.RecoveryFingerprint, expected, message, req.RecoverySignature) == nil {
		return nil
	}
	// A normal renewal may also have installed its new key locally before its
	// commit reached the master. Accept only that exact, recorded successor of
	// the currently pinned key, never a fresh certificate from the revoked CA.
	var renewals []model.ControlIdentityRenewal
	if err := pairingDB().Where("guid = ? AND old_fingerprint = ?", row.ExpectedGUID, row.RecoveryFingerprint).Find(&renewals).Error; err != nil {
		return err
	}
	for _, renewal := range renewals {
		peer, err := cluster.PeerFromPEM(renewal.CertPEM)
		if err == nil && peer.Identity == expected && cluster.VerifyRecoveryProof(req.RecoveryCert, peer.Fingerprint, expected, message, req.RecoverySignature) == nil {
			return nil
		}
	}
	// A commit response may have been lost after the source installed its new
	// identity. Only the exact public identity issued by this master in its CA
	// migration task may replace the old key proof in this case.
	var recipients []model.ControlCARecipient
	if err := pairingDB().Where("node_id = ? AND guid = ? AND cert_pem <> ?", node.Id, row.ExpectedGUID, "").Find(&recipients).Error; err != nil {
		return err
	}
	for _, recipient := range recipients {
		var oldPeer cluster.Peer
		if json.Unmarshal([]byte(recipient.OldPeer), &oldPeer) == nil && oldPeer.Identity == expected && oldPeer.Fingerprint == row.RecoveryFingerprint && oldPeer.PendingFingerprint != "" && cluster.VerifyRecoveryProof(req.RecoveryCert, oldPeer.PendingFingerprint, expected, message, req.RecoverySignature) == nil {
			return nil
		}
		peer, _, err := cluster.ValidateIdentityCertificate(recipient.CertPEM, ca, expected)
		if err == nil && cluster.VerifyRecoveryProof(req.RecoveryCert, peer.Fingerprint, expected, message, req.RecoverySignature) == nil {
			return nil
		}
	}
	return pairingError(403, "recovery_identity_proof_required")
}

func removePeerTx(tx *gorm.DB, guid string) error {
	var row model.Setting
	if err := tx.Where("key = ?", settingControlPeers).First(&row).Error; err != nil {
		return err
	}
	var peers []cluster.Peer
	if err := json.Unmarshal([]byte(row.Value), &peers); err != nil {
		return err
	}
	filtered := make([]cluster.Peer, 0, len(peers))
	for _, p := range peers {
		if p.GUID != guid {
			filtered = append(filtered, p)
		}
	}
	data, _ := json.Marshal(filtered)
	return putPairingSetting(tx, settingControlPeers, string(data))
}

// Recovery is an explicit local-root operation, never an HTTP role switch.
// Its one-time command binds the existing slave and the same managing master.
func (s *PairingService) StartRecovery(req JoinPairingRequest) (PairingView, error) {
	if !req.Profile.Recovery {
		return PairingView{}, pairingError(400, "invalid_recovery_profile")
	}
	return s.startJoinMode(req, false, true)
}

func (s *PairingService) createRecoveryEnrollment(req CreateEnrollmentRequest) (CreatedEnrollment, error) {
	controlPKIMu.Lock()
	defer controlPKIMu.Unlock()
	enrollmentMu.Lock()
	defer enrollmentMu.Unlock()
	settings := &SettingService{}
	self, err := settings.ControlIdentity()
	if err != nil {
		return CreatedEnrollment{}, err
	}
	if self.Role != cluster.RoleMaster {
		return CreatedEnrollment{}, pairingError(403, "only_master_can_enroll_nodes")
	}
	var node model.Node
	if req.ExistingNodeID < 1 {
		return CreatedEnrollment{}, pairingError(400, "invalid_recovery_profile")
	}
	if err := pairingDB().First(&node, req.ExistingNodeID).Error; err != nil {
		return CreatedEnrollment{}, err
	}
	if !node.ControlConnection || !node.ControlRecoveryRequired || !validPairingID(node.Guid) {
		return CreatedEnrollment{}, pairingError(409, "control_recovery_not_required")
	}
	address, err := normalizeRecoveryMaster(req.MasterAddress)
	if err != nil {
		return CreatedEnrollment{}, err
	}
	cfg, err := settings.GetControlConfig()
	if err != nil {
		return CreatedEnrollment{}, err
	}
	if !cfg.Enabled {
		return CreatedEnrollment{}, pairingError(409, "control_listener_disabled")
	}
	own, err := settings.EnsureControlCredentials()
	if err != nil {
		return CreatedEnrollment{}, err
	}
	peer, err := controlPeer(own)
	if err != nil {
		return CreatedEnrollment{}, err
	}
	token, err := randomPairingSecret()
	if err != nil {
		return CreatedEnrollment{}, err
	}
	row := model.NodeEnrollment{
		ID: uuid.NewString(), Name: node.Name, ExistingNodeID: node.Id, ActiveNodeID: &node.Id, ExpectedGUID: node.Guid, MigrationSnapshot: migrationSnapshot(&node), OriginalEnable: node.ControlRecoveryEnable, Recovery: true, RecoveryFingerprint: node.PinnedCertSha256,
		TokenHash: pairingHash(token), Status: PairingPending, ExpiresAt: time.Now().Add(cluster.EnrollmentTTL).UnixMilli(), AllowPrivateAddress: req.AllowPrivateAddress,
	}
	err = pairingDB().Transaction(func(tx *gorm.DB) error {
		now := time.Now().UnixMilli()
		if e := tx.Model(&model.NodeEnrollment{}).Where("active_node_id = ? AND ((status = ? AND expires_at <= ?) OR (status IN ? AND resume_until <= ?))", node.Id, PairingPending, now, []string{PairingIssued, PairingVerifying, PairingProvisioning}, now).Updates(map[string]any{"status": PairingExpired, "active_node_id": nil, "active_guid": nil, "active_name": nil, "registration": ""}).Error; e != nil {
			return e
		}
		if e := tx.Create(&row).Error; e != nil {
			return pairingError(409, "migration_already_pending")
		}
		return tx.Model(&model.ControlCARecipient{}).Where("node_id = ? AND status IN ?", node.Id, []string{"pending", "signed", "staged"}).Update("status", "manual").Error
	})
	if err != nil {
		return CreatedEnrollment{}, err
	}
	return CreatedEnrollment{PairingView: enrollmentView(&row), Profile: cluster.PairingProfile{EnrollmentID: row.ID, MasterAddress: address, MasterPort: cfg.Port, Master: peer, Token: token, ExpiresAt: row.ExpiresAt, Recovery: true, SlaveGUID: node.Guid}}, nil
}

func registerRecoveryNode(row *model.NodeEnrollment, req cluster.RegisterRequest, peer cluster.Peer, address, basePath string) (cluster.PairingReceipt, error) {
	settings := &SettingService{}
	own, err := settings.EnsureControlCredentials()
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	master, err := controlPeer(own)
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	peer.AcknowledgedLocalFingerprint = master.Fingerprint
	controlSettingsMu.Lock()
	defer controlSettingsMu.Unlock()
	node := &model.Node{Guid: row.SlaveGUID, ApiToken: req.AdminToken, Scheme: "https", Port: req.Port, BasePath: basePath, TlsVerifyMode: "mtls", PinnedCertSha256: peer.Fingerprint, AllowPrivateAddress: row.AllowPrivateAddress}
	err = pairingDB().Transaction(func(tx *gorm.DB) error {
		old, e := checkMigrationNode(tx, row)
		if e != nil {
			return e
		}
		node.Address = old.Address
		if e := commitMigrationNode(tx, row, node); e != nil {
			return e
		}
		// Emergency rotation removed this peer. Expired-identity recovery may still
		// have its old entry, which only an explicit recovery task may replace.
		if e := removePeerTx(tx, row.SlaveGUID); e != nil {
			return e
		}
		if e := trustPairingPeer(tx, peer); e != nil {
			return e
		}
		if e := tx.Model(&model.Node{}).Where("id = ?", old.Id).Updates(map[string]any{"enable": false, "control_recovery_required": false}).Error; e != nil {
			return e
		}
		return tx.Model(row).Updates(map[string]any{"status": PairingRegistered, "node_id": old.Id, "address": address, "port": req.Port, "base_path": basePath, "admin_hash": pairingHash(req.AdminToken), "last_error": ""}).Error
	})
	if err != nil {
		return cluster.PairingReceipt{}, err
	}
	invalidateControlNode(node.Id)
	if req.PublicIP != nil {
		_ = (&NodeIPService{}).Store(context.Background(), row.SlaveGUID, *req.PublicIP, time.Now())
	}
	return cluster.PairingReceipt{NodeID: node.Id, Status: PairingRegistered}, nil
}

// Only a slave with an existing identity may run an empty, fail-closed listener
// after expiry. This keeps proxy startup possible and lets local recovery queue
// a new, pinned enrollment; no expired credential is accepted by TLS.
func (s *PairingService) CanStartControlWithoutIdentity() (bool, error) {
	pending, err := s.IsPendingSlaveInstall()
	if err != nil || pending {
		return pending, err
	}
	settings := &SettingService{}
	self, err := settings.ControlIdentity()
	if err != nil {
		return false, err
	}
	if self.Role != cluster.RoleSlave {
		return false, nil
	}
	row, err := settings.getSetting(settingControlCredentials)
	if err != nil {
		return false, err
	}
	return row.Value != "", nil
}

func expireControlPeers() error {
	settings := &SettingService{}
	active, err := settings.EnsureControlCredentials()
	if err != nil {
		return err
	}
	own, err := controlPeer(active)
	if err != nil {
		return err
	}
	var state identityRotation
	if err := readPKISetting(settingControlRotation, &state); err != nil {
		return err
	}
	controlSettingsMu.Lock()
	defer controlSettingsMu.Unlock()
	peers, err := settings.controlPeersLocked()
	if err != nil {
		return err
	}
	for _, peer := range peers {
		if peer.Role != cluster.RoleSlave {
			continue
		}
		expired := peer.CertificateNotAfter > 0 && peer.CertificateNotAfter <= time.Now().UnixMilli()
		missed := state.PreviousUntil > 0 && state.PreviousUntil <= time.Now().UnixMilli() && peer.AcknowledgedLocalFingerprint != own.Fingerprint
		if !expired && !missed {
			continue
		}
		err = pairingDB().Transaction(func(tx *gorm.DB) error {
			var node model.Node
			if e := tx.Where("guid = ? AND control_connection = ?", peer.GUID, true).First(&node).Error; e != nil {
				return e
			}
			enabled := node.Enable
			if node.ControlRecoveryRequired {
				enabled = node.ControlRecoveryEnable
			}
			if e := tx.Model(&node).Updates(map[string]any{"enable": false, "control_recovery_required": true, "control_recovery_enable": enabled}).Error; e != nil {
				return e
			}
			return removePeerTx(tx, peer.GUID)
		})
		if err != nil {
			return err
		}
		invalidateControlNode(0)
	}
	return nil
}
