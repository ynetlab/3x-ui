package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/crypto/nodetoken"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	panelcrypto "github.com/mhsanaei/3x-ui/v3/internal/util/crypto"
)

type caStage struct {
	ID          string              `json:"id"`
	Deadline    int64               `json:"deadline"`
	CA          string              `json:"ca"`
	Master      cluster.Peer        `json:"master"`
	CSR         string              `json:"csr"`
	Key         string              `json:"key"`
	Credentials cluster.Credentials `json:"credentials"`
	Done        bool                `json:"done"`
}
type caRequest struct {
	ID         string `json:"id"`
	Deadline   int64  `json:"deadline,omitempty"`
	CA         string `json:"ca,omitempty"`
	MasterCert string `json:"masterCert,omitempty"`
	Cert       string `json:"cert,omitempty"`
}
type caReply struct {
	CSR   string `json:"csr,omitempty"`
	Ready bool   `json:"ready"`
}
type caMigrationPayload struct {
	Credentials []cluster.Credentials `json:"credentials"`
}

// Rotation routes never grant ordinary management authority to a staged CA.
func registerCAControlRoutes(router *cluster.Router, isAdmin func(string) bool) {
	for _, op := range []string{"prepare", "stage", "verify", "commit"} {
		operation := op
		router.Handle("POST /cluster/v1/control-ca/"+operation, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			controlPKIMu.Lock()
			defer controlPKIMu.Unlock()
			var req caRequest
			if err := readPairingJSON(w, r, &req); err != nil {
				pairingJSON(w, nil, err)
				return
			}
			if !validPairingID(req.ID) {
				pairingJSON(w, nil, pairingError(400, "invalid_ca_rotation"))
				return
			}
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || isAdmin == nil || !isAdmin(token) {
				pairingJSON(w, nil, pairingError(403, "full_admin_token_required"))
				return
			}
			settings := &SettingService{}
			var joining int64
			if err := pairingDB().Model(&model.NodeJoinJob{}).Where("active_slot IS NOT NULL AND recovery = ?", true).Count(&joining).Error; err != nil {
				pairingJSON(w, nil, err)
				return
			}
			if joining > 0 {
				pairingJSON(w, nil, pairingError(409, "control_pairing_in_progress"))
				return
			}
			self, err := settings.ControlIdentity()
			if err != nil || self.Role != cluster.RoleSlave {
				pairingJSON(w, nil, pairingError(403, "only_slave_accepts_ca_rotation"))
				return
			}
			var stage caStage
			if err := readPKISetting(settingControlCAStage, &stage); err != nil {
				pairingJSON(w, nil, err)
				return
			}
			auth := cluster.Authorizer{Self: settings.ControlIdentity, LookupPeer: settings.LookupControlPeer}
			if operation == "verify" || operation == "commit" {
				if stage.ID != req.ID || stage.Deadline <= time.Now().UnixMilli() {
					pairingJSON(w, nil, pairingError(403, "ca_rotation_expired"))
					return
				}
				auth.LookupPeer = func(ctx context.Context, guid string) (cluster.Peer, error) {
					bound, e := settings.LookupControlPeer(ctx, guid)
					if e != nil || bound.Role != cluster.RoleMaster || guid != stage.Master.GUID {
						return cluster.Peer{}, cluster.ErrPeerNotTrusted
					}
					return stage.Master, nil
				}
			}
			auth.RequireMaster(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				controlSettingsMu.Lock()
				defer controlSettingsMu.Unlock()
				if operation == "prepare" {
					master, _, e := cluster.ValidateIdentityCertificate(req.MasterCert, req.CA, cluster.Identity{GUID: mustAuthenticatedGUID(r), Role: cluster.RoleMaster})
					if e != nil {
						pairingJSON(w, nil, pairingError(400, "invalid_ca_rotation"))
						return
					}
					if req.Deadline <= time.Now().UnixMilli() || req.Deadline > time.Now().Add(cluster.EnrollmentTTL+time.Minute).UnixMilli() {
						pairingJSON(w, nil, pairingError(400, "invalid_ca_rotation"))
						return
					}
					if stage.ID == req.ID {
						if stage.CA != req.CA || stage.Master.Fingerprint != master.Fingerprint {
							pairingJSON(w, nil, pairingError(409, "ca_rotation_changed"))
							return
						}
					} else {
						if stage.ID != "" && !stage.Done && stage.Deadline > time.Now().UnixMilli() {
							pairingJSON(w, nil, pairingError(409, "ca_rotation_in_progress"))
							return
						}
						csr, key, e := cluster.NewCSR()
						if e != nil {
							pairingJSON(w, nil, e)
							return
						}
						stage = caStage{ID: req.ID, Deadline: req.Deadline, CA: req.CA, Master: master, CSR: string(csr), Key: string(key)}
						if e = writePKISetting(pairingDB(), settingControlCAStage, stage); e != nil {
							pairingJSON(w, nil, e)
							return
						}
					}
					pairingJSON(w, caReply{CSR: stage.CSR}, nil)
					return
				}
				if stage.ID != req.ID || stage.Deadline <= time.Now().UnixMilli() {
					pairingJSON(w, nil, pairingError(403, "ca_rotation_expired"))
					return
				}
				if operation == "stage" {
					credentials := cluster.Credentials{CACertPEM: stage.CA, CertPEM: req.Cert, KeyPEM: stage.Key}
					_, _, identity, e := credentials.Load()
					if e != nil || identity != self {
						pairingJSON(w, nil, pairingError(400, "invalid_ca_rotation_identity"))
						return
					}
					if stage.Credentials.CertPEM != "" && stage.Credentials.CertPEM != req.Cert {
						pairingJSON(w, nil, pairingError(409, "ca_rotation_changed"))
						return
					}
					stage.Credentials = credentials
					pairingJSON(w, caReply{Ready: true}, writePKISetting(pairingDB(), settingControlCAStage, stage))
					return
				}
				if !stage.Done {
					if _, _, identity, e := stage.Credentials.Load(); e != nil || identity != self {
						pairingJSON(w, nil, pairingError(409, "ca_rotation_not_staged"))
						return
					}
					// A pooled old-CA TLS connection cannot call commit after staging.
					if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || cluster.Fingerprint(r.TLS.PeerCertificates[0]) != stage.Master.Fingerprint {
						pairingJSON(w, nil, pairingError(403, "ca_rotation_proof_required"))
						return
					}
					if operation == "commit" {
						credentials := stage.Credentials
						stage.Done = true
						stage.Credentials = cluster.Credentials{}
						stage.Key = ""
						stage.CSR = ""
						err := pairingDB().Transaction(func(tx *gorm.DB) error {
							if e := storeCredentialsTx(tx, credentials); e != nil {
								return e
							}
							if e := replacePeerTx(tx, stage.Master); e != nil {
								return e
							}
							if e := tx.Model(&model.NodeJoinJob{}).Where("active_slot IS NOT NULL AND master_guid = ? AND status = ? AND recovery = ?", stage.Master.GUID, PairingConfirming, false).Updates(map[string]any{"active_slot": nil, "status": PairingCompleted, "payload": "", "last_error": ""}).Error; e != nil {
								return e
							}
							if e := writePKISetting(tx, settingControlRotation, identityRotation{}); e != nil {
								return e
							}
							return writePKISetting(tx, settingControlCAStage, stage)
						})
						if err != nil {
							pairingJSON(w, nil, err)
							return
						}
						invalidateControlNode(0)
					}
				}
				pairingJSON(w, caReply{Ready: true}, nil)
			})).ServeHTTP(w, r)
		}))
	}
}

func mustAuthenticatedGUID(r *http.Request) string {
	identity, _ := cluster.AuthenticatedPeer(r.Context())
	return identity.GUID
}

type ControlPKIStatus struct {
	CAFingerprint     string `json:"caFingerprint"`
	CAExpiresAt       int64  `json:"caExpiresAt"`
	IdentityExpiresAt int64  `json:"identityExpiresAt"`
	LastError         string `json:"lastError,omitempty"`
	JobID             string `json:"jobId,omitempty"`
	Status            string `json:"status,omitempty"`
	Total             int64  `json:"total"`
	Migrated          int64  `json:"migrated"`
	Recovery          int64  `json:"recovery"`
	Deadline          int64  `json:"deadline,omitempty"`
}

func ControlCertificateStatus() (ControlPKIStatus, error) {
	settings := &SettingService{}
	self, err := settings.ControlIdentity()
	if err != nil {
		return ControlPKIStatus{}, err
	}
	if self.Role != cluster.RoleMaster {
		return ControlPKIStatus{}, pairingError(403, "only_master_can_rotate_ca")
	}
	active, err := settings.EnsureControlCredentials()
	if err != nil {
		return ControlPKIStatus{}, err
	}
	leaf, _, _, err := active.Load()
	if err != nil {
		return ControlPKIStatus{}, err
	}
	ca, err := cluster.ValidateControlCA(active.CACertPEM)
	if err != nil {
		return ControlPKIStatus{}, err
	}
	result := ControlPKIStatus{CAFingerprint: cluster.Fingerprint(ca), CAExpiresAt: ca.NotAfter.UnixMilli(), IdentityExpiresAt: leaf.Leaf.NotAfter.UnixMilli()}
	var state identityRotation
	if err := readPKISetting(settingControlRotation, &state); err != nil {
		return result, err
	}
	result.LastError = state.LastError
	var job model.ControlCAChange
	if err := pairingDB().Order("created_at DESC").First(&job).Error; err == nil {
		result.JobID = job.ID
		result.Status = job.Status
		result.Deadline = job.Deadline
		if err := pairingDB().Model(&model.ControlCARecipient{}).Where("change_id = ?", job.ID).Count(&result.Total).Error; err != nil {
			return result, err
		}
		if err := pairingDB().Model(&model.ControlCARecipient{}).Where("change_id = ? AND status = ?", job.ID, "completed").Count(&result.Migrated).Error; err != nil {
			return result, err
		}
	} else if !database.IsNotFound(err) {
		return result, err
	}
	err = pairingDB().Model(&model.Node{}).Where("control_recovery_required = ?", true).Count(&result.Recovery).Error
	return result, err
}

func RotateControlCA(confirm bool) (ControlPKIStatus, error) {
	if !confirm {
		return ControlPKIStatus{}, pairingError(400, "ca_rotation_confirmation_required")
	}
	controlPKIMu.Lock()
	defer controlPKIMu.Unlock()
	enrollmentMu.Lock()
	defer enrollmentMu.Unlock()
	settings := &SettingService{}
	self, err := settings.ControlIdentity()
	if err != nil {
		return ControlPKIStatus{}, err
	}
	if self.Role != cluster.RoleMaster {
		return ControlPKIStatus{}, pairingError(403, "only_master_can_rotate_ca")
	}
	old, err := settings.EnsureControlCredentials()
	if err != nil {
		return ControlPKIStatus{}, err
	}
	var previous identityRotation
	if err = readPKISetting(settingControlRotation, &previous); err != nil {
		return ControlPKIStatus{}, err
	}
	oldCreds := []cluster.Credentials{old}
	if previous.PreviousUntil > time.Now().UnixMilli() {
		oldCreds = append(oldCreds, previous.Previous)
	}
	ca, err := panelcrypto.GenerateNodeCAForYears("3x-ui control CA", 30)
	if err != nil {
		return ControlPKIStatus{}, err
	}
	csr, key, err := cluster.NewCSR()
	if err != nil {
		return ControlPKIStatus{}, err
	}
	cert, err := cluster.IssueIdentity(ca, csr, self)
	if err != nil {
		return ControlPKIStatus{}, err
	}
	active := cluster.Credentials{CACertPEM: string(ca.CertPEM), CertPEM: string(cert), KeyPEM: string(key)}
	root, err := cluster.ValidateControlCA(string(ca.CertPEM))
	if err != nil {
		return ControlPKIStatus{}, err
	}
	slot := "local"
	job := model.ControlCAChange{ID: uuid.NewString(), ActiveSlot: &slot, MasterGUID: self.GUID, Fingerprint: cluster.Fingerprint(root), MasterCertPEM: string(cert), Status: "migrating", Deadline: time.Now().Add(cluster.EnrollmentTTL).UnixMilli()}
	data, err := json.Marshal(caMigrationPayload{Credentials: oldCreds})
	if err != nil {
		return ControlPKIStatus{}, err
	}
	job.Payload, err = nodetoken.EncryptBound([]byte("control-ca/"+job.ID), string(data))
	if err != nil {
		return ControlPKIStatus{}, err
	}
	controlSettingsMu.Lock()
	peers, err := settings.controlPeersLocked()
	if err != nil {
		controlSettingsMu.Unlock()
		return ControlPKIStatus{}, err
	}
	err = pairingDB().Transaction(func(tx *gorm.DB) error {
		var current int64
		if e := tx.Model(&model.ControlCAChange{}).Where("active_slot IS NOT NULL").Count(&current).Error; e != nil {
			return e
		}
		if current != 0 {
			return pairingError(409, "ca_rotation_in_progress")
		}
		var nodes []model.Node
		if e := tx.Where("control_connection = ?", true).Find(&nodes).Error; e != nil {
			return e
		}
		byGUID := map[string]cluster.Peer{}
		for _, p := range peers {
			byGUID[p.GUID] = p
		}
		if e := tx.Create(&job).Error; e != nil {
			return e
		}
		for _, node := range nodes {
			enabled := node.Enable
			if node.ControlRecoveryRequired {
				enabled = node.ControlRecoveryEnable
			}
			var confirming model.NodeEnrollment
			if e := tx.Where("node_id = ? AND status = ?", node.Id, PairingRegistered).First(&confirming).Error; e == nil {
				enabled = confirming.ExistingNodeID == 0 || confirming.OriginalEnable
			} else if !database.IsNotFound(e) {
				return e
			}
			oldPeer, present := byGUID[node.Guid]
			peerJSON, _ := json.Marshal(oldPeer)
			updates := map[string]any{"enable": false, "control_recovery_required": true, "control_recovery_enable": enabled}
			if e := tx.Model(&node).Updates(updates).Error; e != nil {
				return e
			}
			node.Enable = false
			node.ControlRecoveryRequired = true
			node.ControlRecoveryEnable = enabled
			recipient := model.ControlCARecipient{ChangeID: job.ID, NodeID: node.Id, GUID: node.Guid, OldPeer: string(peerJSON), Snapshot: migrationSnapshot(&node), OriginalEnable: enabled, Status: "pending"}
			if !present || oldPeer.Role != cluster.RoleSlave {
				recipient.Status = "recovery"
			}
			if e := tx.Create(&recipient).Error; e != nil {
				return e
			}
		}
		caJSON, _ := json.Marshal(ca)
		if e := putPairingSetting(tx, settingControlCA, string(caJSON)); e != nil {
			return e
		}
		if e := storeCredentialsTx(tx, active); e != nil {
			return e
		}
		if e := putPairingSetting(tx, settingControlPeers, "[]"); e != nil {
			return e
		}
		if e := writePKISetting(tx, settingControlRotation, identityRotation{}); e != nil {
			return e
		}
		if e := tx.Model(&model.ControlIdentityRenewal{}).Where("active_guid IS NOT NULL").Updates(map[string]any{"active_guid": nil, "status": "revoked"}).Error; e != nil {
			return e
		}
		return tx.Model(&model.NodeEnrollment{}).Where("status IN ?", []string{PairingPending, PairingIssued, PairingVerifying, PairingProvisioning, PairingRegistered}).Updates(map[string]any{"status": PairingFailed, "active_name": nil, "active_guid": nil, "active_node_id": nil, "registration": "", "last_error": "control_ca_revoked"}).Error
	})
	controlSettingsMu.Unlock()
	if err != nil {
		return ControlPKIStatus{}, err
	}
	invalidateControlNode(0)
	return ControlCertificateStatus()
}

func stepCAChange(ctx context.Context) error {
	var job model.ControlCAChange
	if err := pairingDB().Where("active_slot IS NOT NULL").First(&job).Error; err != nil {
		if database.IsNotFound(err) {
			return nil
		}
		return err
	}
	if job.Deadline <= time.Now().UnixMilli() {
		return finishCAChange(&job)
	}
	self, err := (&SettingService{}).ControlIdentity()
	if err != nil {
		return err
	}
	if self.GUID != job.MasterGUID || self.Role != cluster.RoleMaster {
		return errors.New("ca_rotation_host_changed")
	}
	var recipients []model.ControlCARecipient
	if err := pairingDB().Where("change_id = ? AND status IN ? AND next_attempt_at <= ?", job.ID, []string{"pending", "signed", "staged"}, time.Now().UnixMilli()).Order("next_attempt_at ASC, id ASC").Limit(4).Find(&recipients).Error; err != nil {
		return err
	}
	// Bound network concurrency without holding the identity/pairing mutex.
	// Manual recovery reserves the recipient in the DB and wins final commit.
	var tasks sync.WaitGroup
	failures := make(chan error, len(recipients))
	for i := range recipients {
		r := &recipients[i]
		tasks.Add(1)
		go func() {
			defer tasks.Done()
			err := migrateCARecipient(ctx, &job, r)
			if err != nil {
				delay := min(time.Second<<min(r.Attempts, 6), time.Minute)
				if e := pairingDB().Model(r).Updates(map[string]any{"attempts": r.Attempts + 1, "last_error": pairingFailureCode(err), "next_attempt_at": time.Now().Add(delay).UnixMilli()}).Error; e != nil {
					failures <- e
				}
			}
		}()
	}
	tasks.Wait()
	close(failures)
	for failure := range failures {
		if failure != nil {
			return failure
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if job.Deadline <= time.Now().UnixMilli() {
		return finishCAChange(&job)
	}
	var pending int64
	if err := pairingDB().Model(&model.ControlCARecipient{}).Where("change_id = ? AND status IN ?", job.ID, []string{"pending", "signed", "staged"}).Count(&pending).Error; err != nil {
		return err
	}
	if pending == 0 {
		return finishCAChange(&job)
	}
	return nil
}

func finishCAChange(job *model.ControlCAChange) error {
	return pairingDB().Transaction(func(tx *gorm.DB) error {
		if e := tx.Model(&model.ControlCARecipient{}).Where("change_id = ? AND status NOT IN ?", job.ID, []string{"completed", "manual"}).Update("status", "recovery").Error; e != nil {
			return e
		}
		var count int64
		if e := tx.Model(&model.ControlCARecipient{}).Where("change_id = ? AND status <> ?", job.ID, "completed").Count(&count).Error; e != nil {
			return e
		}
		status := "completed"
		if count > 0 {
			status = "recovery_required"
		}
		return tx.Model(job).Updates(map[string]any{"status": status, "active_slot": nil, "payload": ""}).Error
	})
}

func migrateCARecipient(ctx context.Context, job *model.ControlCAChange, r *model.ControlCARecipient) error {
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(job.Deadline))
	defer cancel()
	var node model.Node
	if err := pairingDB().First(&node, r.NodeID).Error; err != nil {
		return err
	}
	if !node.ControlRecoveryRequired || node.Guid != r.GUID || migrationSnapshot(&node) != r.Snapshot {
		return pairingDB().Model(r).Updates(map[string]any{"status": "recovery", "last_error": "migration_node_changed"}).Error
	}
	var reserved int64
	if err := pairingDB().Model(&model.NodeEnrollment{}).Where("active_node_id = ?", node.Id).Count(&reserved).Error; err != nil {
		return err
	}
	if reserved > 0 {
		return pairingDB().Model(r).Update("status", "manual").Error
	}
	token, err := nodetoken.Decrypt(node.Id, node.ApiToken)
	if err != nil {
		return err
	}
	active, err := (&SettingService{}).EnsureControlCredentials()
	if err != nil {
		return err
	}
	ca, err := cluster.ValidateControlCA(active.CACertPEM)
	if err != nil || cluster.Fingerprint(ca) != job.Fingerprint {
		return errors.New("ca_rotation_changed")
	}
	req := caRequest{ID: job.ID, Deadline: job.Deadline, CA: active.CACertPEM, MasterCert: job.MasterCertPEM}
	call := func(cfg *tls.Config, op string, request caRequest, out any) error {
		return pairingRPC(ctx, cfg, node.AllowPrivateAddress, pairingURL(node.Address, node.Port, "/cluster/v1/control-ca/"+op), token, request, out)
	}
	if r.Status != "staged" {
		var peer cluster.Peer
		if err := json.Unmarshal([]byte(r.OldPeer), &peer); err != nil {
			return err
		}
		data, err := nodetoken.DecryptBound([]byte("control-ca/"+job.ID), job.Payload)
		if err != nil {
			return err
		}
		var payload caMigrationPayload
		if err = json.Unmarshal([]byte(data), &payload); err != nil {
			return err
		}
		if len(payload.Credentials) == 0 {
			return errors.New("invalid_ca_rotation_payload")
		}
		own := payload.Credentials[0]
		if peer.AcknowledgedLocalFingerprint != "" {
			for _, candidate := range payload.Credentials {
				p, e := controlPeer(candidate)
				if e == nil && p.Fingerprint == peer.AcknowledgedLocalFingerprint {
					own = candidate
				}
			}
		}
		cfg, err := cluster.ClientTLS(own, peer)
		if err != nil {
			return err
		}
		var reply caReply
		if err = call(cfg, "prepare", req, &reply); err != nil {
			return err
		}
		if r.CertPEM == "" {
			cert, _, err := (&SettingService{}).IssueControlIdentity([]byte(reply.CSR), cluster.Identity{GUID: r.GUID, Role: cluster.RoleSlave})
			if err != nil {
				return err
			}
			r.CertPEM = string(cert)
			r.CSRHash = pairingHash(reply.CSR)
			result := pairingDB().Model(r).Where("status IN ?", []string{"pending", "signed"}).Updates(map[string]any{"cert_pem": r.CertPEM, "csr_hash": r.CSRHash, "status": "signed"})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return pairingError(409, "migration_node_changed")
			}
		} else if r.CSRHash != pairingHash(reply.CSR) {
			return errors.New("ca_rotation_changed")
		}
		req.Cert = r.CertPEM
		if err = call(cfg, "stage", req, &reply); err != nil {
			return err
		}
		result := pairingDB().Model(r).Where("status IN ?", []string{"pending", "signed"}).Update("status", "staged")
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return pairingError(409, "migration_node_changed")
		}
		r.Status = "staged"
	}
	peer, _, err := cluster.ValidateIdentityCertificate(r.CertPEM, active.CACertPEM, cluster.Identity{GUID: r.GUID, Role: cluster.RoleSlave})
	if err != nil {
		return err
	}
	own, err := controlPeer(active)
	if err != nil {
		return err
	}
	peer.AcknowledgedLocalFingerprint = own.Fingerprint
	cfg, err := cluster.ClientTLS(active, peer)
	if err != nil {
		return err
	}
	var reply caReply
	if err = call(cfg, "verify", req, &reply); err != nil {
		return err
	}
	if !reply.Ready {
		return errors.New("ca_rotation_not_staged")
	}
	if err = call(cfg, "commit", req, &reply); err != nil {
		return err
	}
	var proof struct {
		Success bool `json:"success"`
	}
	if err = pairingRPC(ctx, cfg, node.AllowPrivateAddress, pairingURL(node.Address, node.Port, node.BasePath+"panel/api/setting/all"), token, struct{}{}, &proof); err != nil {
		return err
	}
	if !proof.Success {
		return errors.New("paired_node_management_not_ready")
	}
	controlSettingsMu.Lock()
	defer controlSettingsMu.Unlock()
	err = pairingDB().Transaction(func(tx *gorm.DB) error {
		var reservation model.ControlCARecipient
		if e := tx.First(&reservation, r.ID).Error; e != nil {
			return e
		}
		if reservation.Status != "staged" {
			return pairingError(409, "migration_node_changed")
		}
		var stored model.Setting
		if e := tx.Where("key = ?", settingControlCredentials).First(&stored).Error; e != nil {
			return e
		}
		var currentCredentials cluster.Credentials
		if json.Unmarshal([]byte(stored.Value), &currentCredentials) != nil || currentCredentials != active {
			return pairingError(409, "ca_rotation_host_changed")
		}
		var current model.Node
		if e := tx.First(&current, node.Id).Error; e != nil {
			return e
		}
		if migrationSnapshot(&current) != r.Snapshot {
			return pairingError(409, "migration_node_changed")
		}
		if e := trustPairingPeer(tx, peer); e != nil {
			return e
		}
		if e := tx.Model(&current).Updates(map[string]any{"pinned_cert_sha256": peer.Fingerprint, "control_recovery_required": false, "control_recovery_enable": false, "enable": r.OriginalEnable}).Error; e != nil {
			return e
		}
		return tx.Model(r).Updates(map[string]any{"status": "completed", "last_error": ""}).Error
	})
	if err == nil {
		invalidateControlNode(node.Id)
	}
	return err
}
