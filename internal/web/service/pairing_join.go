package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/crypto/nodetoken"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/nodeip"
	panelcrypto "github.com/mhsanaei/3x-ui/v3/internal/util/crypto"
	"github.com/mhsanaei/3x-ui/v3/internal/util/netsafe"
	"github.com/mhsanaei/3x-ui/v3/internal/web/runtime"
	"github.com/mhsanaei/3x-ui/v3/internal/web/websocket"
	"gorm.io/gorm"
)

type JoinPairingRequest struct {
	Profile            cluster.PairingProfile `json:"profile"`
	Address            string                 `json:"address"`
	Port               int                    `json:"port"`
	AllowPrivateMaster bool                   `json:"allowPrivateMaster"`
}

type joinSecrets struct {
	Request           JoinPairingRequest  `json:"request"`
	CSR               string              `json:"csr"`
	KeyPEM            string              `json:"keyPem"`
	Credentials       cluster.Credentials `json:"credentials"`
	AdminToken        string              `json:"adminToken"`
	BasePath          string              `json:"basePath"`
	PublicIP          *nodeip.Report      `json:"publicIp,omitempty"`
	PanelPort         int                 `json:"panelPort,omitempty"`
	RecoveryCert      string              `json:"recoveryCert,omitempty"`
	RecoverySignature string              `json:"recoverySignature,omitempty"`
}

func sealJoin(id string, secrets joinSecrets) (string, error) {
	data, err := json.Marshal(secrets)
	if err != nil {
		return "", err
	}
	return nodetoken.EncryptBound([]byte("node-pairing/"+id), string(data))
}

func openJoin(row *model.NodeJoinJob) (joinSecrets, error) {
	data, err := nodetoken.DecryptBound([]byte("node-pairing/"+row.ID), row.Payload)
	if err != nil {
		return joinSecrets{}, err
	}
	var secrets joinSecrets
	err = json.Unmarshal([]byte(data), &secrets)
	return secrets, err
}

func (s *PairingService) StartJoin(req JoinPairingRequest) (PairingView, error) {
	return s.startJoin(req, false)
}

func (s *PairingService) startJoin(req JoinPairingRequest, newInstall bool) (PairingView, error) {
	return s.startJoinMode(req, newInstall, false)
}
func (s *PairingService) startJoinMode(req JoinPairingRequest, newInstall, recovery bool) (PairingView, error) {
	controlPKIMu.Lock()
	defer controlPKIMu.Unlock()
	if req.Profile.Recovery != recovery {
		return PairingView{}, pairingError(400, "invalid_recovery_profile")
	}
	if !validPairingID(req.Profile.EnrollmentID) || req.Profile.Master.Validate() != nil || req.Profile.Master.Role != cluster.RoleMaster {
		return PairingView{}, pairingError(400, "invalid_pairing_profile")
	}
	address, err := netsafe.NormalizeHost(req.Address)
	if err != nil && req.Address != "" {
		return PairingView{}, pairingError(400, "invalid_slave_address")
	}
	masterAddress, err := netsafe.NormalizeHost(req.Profile.MasterAddress)
	if err != nil || req.Profile.MasterPort < 1 || req.Profile.MasterPort > 65535 || len(req.Profile.Token) < 16 || len(req.Profile.Token) > 512 {
		return PairingView{}, pairingError(400, "invalid_pairing_profile")
	}
	req.Address, req.Profile.MasterAddress = address, masterAddress
	settings := &SettingService{}
	config, err := settings.GetControlConfig()
	if err != nil {
		return PairingView{}, err
	}
	if !config.Enabled {
		return PairingView{}, pairingError(409, "control_listener_disabled")
	}
	if req.Port == 0 {
		req.Port = config.Port
	}
	if req.Port < 1 || req.Port > 65535 {
		return PairingView{}, pairingError(400, "invalid_slave_port")
	}
	id := uuid.NewSHA1(uuid.NameSpaceURL, []byte(req.Profile.Master.GUID+"/"+req.Profile.EnrollmentID)).String()
	data, err := json.Marshal(req)
	if err != nil {
		return PairingView{}, err
	}
	hash := pairingHash(string(data))
	joinStepMu.Lock()
	defer joinStepMu.Unlock()
	if row, err := s.join(id); err == nil {
		if row.RequestHash != hash {
			return PairingView{}, pairingError(409, "join_request_changed")
		}
		if newInstall {
			installID, err := settings.getString(settingSlaveInstallPairingID)
			if err != nil {
				return PairingView{}, err
			}
			if installID != id {
				return PairingView{}, pairingError(409, "new_slave_install_requires_empty_panel")
			}
		}
		return joinView(row), nil
	} else if !database.IsNotFound(err) {
		return PairingView{}, err
	}
	if newInstall {
		if err := s.requireFreshSlaveInstall(); err != nil {
			return PairingView{}, err
		}
	}
	self, err := settings.ControlIdentity()
	if err != nil {
		return PairingView{}, err
	}
	if recovery {
		peer, e := settings.LookupControlPeer(context.Background(), req.Profile.Master.GUID)
		if self.Role != cluster.RoleSlave || self.GUID != req.Profile.SlaveGUID || e != nil || peer.Role != cluster.RoleMaster {
			return PairingView{}, pairingError(409, "recovery_identity_mismatch")
		}
	} else if self.Role != cluster.RoleMaster {
		return PairingView{}, pairingError(409, "node_already_in_slave_mode")
	}
	if self.GUID == req.Profile.Master.GUID {
		return PairingView{}, pairingError(409, "cannot_pair_node_with_itself")
	}
	if req.Profile.ExpiresAt <= time.Now().UnixMilli() {
		return PairingView{}, pairingError(410, "enrollment_expired")
	}
	basePath, err := settings.GetBasePath()
	if err != nil {
		return PairingView{}, err
	}
	if newInstall {
		basePath = "/" + uuid.NewString() + "/"
	}
	csr, key, err := cluster.NewCSR()
	if err != nil {
		return PairingView{}, err
	}
	secrets := joinSecrets{Request: req, CSR: string(csr), KeyPEM: string(key), BasePath: basePath}
	if recovery {
		stored, e := settings.getSetting(settingControlCredentials)
		if e != nil {
			return PairingView{}, e
		}
		var old cluster.Credentials
		if e = json.Unmarshal([]byte(stored.Value), &old); e != nil {
			return PairingView{}, e
		}
		secrets.RecoveryCert = old.CertPEM
		secrets.RecoverySignature, err = cluster.SignRecoveryProof(old, cluster.RecoveryMessage(req.Profile.EnrollmentID, self.GUID, secrets.CSR, req.Profile.Master.Fingerprint))
		if err != nil {
			return PairingView{}, pairingError(409, "recovery_identity_proof_required")
		}
	}
	payload, err := sealJoin(id, secrets)
	if err != nil {
		return PairingView{}, err
	}
	slot := "local"
	row := model.NodeJoinJob{ID: id, ActiveSlot: &slot, EnrollmentID: req.Profile.EnrollmentID, MasterGUID: req.Profile.Master.GUID,
		RequestHash: hash, Status: PairingPending, Payload: payload, Deadline: req.Profile.ExpiresAt, Recovery: recovery}
	err = pairingDB().Transaction(func(tx *gorm.DB) error {
		if recovery {
			if e := tx.Model(&model.NodeJoinJob{}).Where("active_slot IS NOT NULL AND master_guid = ? AND (recovery = ? OR status = ?)", req.Profile.Master.GUID, true, PairingConfirming).Updates(map[string]any{"active_slot": nil, "status": PairingFailed, "payload": "", "last_error": "control_recovery_superseded"}).Error; e != nil {
				return e
			}
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		if !newInstall {
			if recovery {
				return writePKISetting(tx, settingControlCAStage, caStage{})
			}
			return nil
		}
		for key, value := range map[string]string{
			settingPanelRole: PanelRoleSlave, settingSlaveInstallPairingID: id,
			"webBasePath": basePath, "webListen": "",
		} {
			if err := putPairingSetting(tx, key, value); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return PairingView{}, pairingError(409, "another_pairing_is_active")
	}
	return joinView(&row), nil
}

func (s *PairingService) ResumeJoin(id string) (PairingView, error) {
	joinStepMu.Lock()
	defer joinStepMu.Unlock()
	row, err := s.join(id)
	if err != nil {
		return PairingView{}, err
	}
	if row.Status == PairingCompleted {
		return joinView(row), nil
	}
	if row.Status == PairingExpired || row.Status == PairingFailed {
		return PairingView{}, pairingError(409, "pairing_terminal_state")
	}
	if err := pairingDB().Model(row).Updates(map[string]any{"next_attempt_at": 0, "failures": 0}).Error; err != nil {
		return PairingView{}, err
	}
	return joinView(row), nil
}

func (s *PairingService) PendingJoin() (*model.NodeJoinJob, joinSecrets, error) {
	var row model.NodeJoinJob
	if err := pairingDB().Where("active_slot = ? AND status IN ?", "local", []string{PairingIssued, PairingConfirming}).First(&row).Error; err != nil {
		return nil, joinSecrets{}, err
	}
	if row.Status != PairingConfirming && row.Deadline <= time.Now().UnixMilli() {
		return nil, joinSecrets{}, pairingError(410, "enrollment_expired")
	}
	secrets, err := openJoin(&row)
	if err != nil {
		return nil, secrets, err
	}
	if _, _, _, err := secrets.Credentials.Load(); err != nil {
		return nil, secrets, err
	}
	return &row, secrets, nil
}

// StepJoin advances one durable step. Only confirmed registration can change
// the local role; a crash or a lost response safely repeats the same request.
func (s *PairingService) StepJoin(ctx context.Context, id string) error {
	controlPKIMu.Lock()
	defer controlPKIMu.Unlock()
	joinStepMu.Lock()
	defer joinStepMu.Unlock()
	row, err := s.join(id)
	if err != nil {
		return err
	}
	if row.Status == PairingCompleted || row.Status == PairingFailed || row.Status == PairingExpired {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if row.Status != PairingConfirming && row.Deadline <= time.Now().UnixMilli() {
		return s.finishUncommittedJoin(row, PairingExpired, "enrollment_expired")
	}
	secrets, err := openJoin(row)
	if err != nil {
		return s.failJoin(row, pairingError(400, "invalid_stored_pairing_credentials"))
	}
	profile := secrets.Request.Profile
	switch row.Status {
	case PairingPending:
		config, err := cluster.BootstrapTLS(profile.Master)
		if err != nil {
			return s.failJoin(row, pairingError(400, "invalid_pairing_profile"))
		}
		self, err := (&SettingService{}).ControlIdentity()
		if err != nil {
			return err
		}
		var response cluster.EnrollResponse
		err = pairingRPC(ctx, config, secrets.Request.AllowPrivateMaster, pairingURL(profile.MasterAddress, profile.MasterPort, "/cluster/v1/enroll"), profile.Token,
			cluster.EnrollRequest{EnrollmentID: profile.EnrollmentID, GUID: self.GUID, CSR: secrets.CSR, RecoveryCert: secrets.RecoveryCert, RecoverySignature: secrets.RecoverySignature}, &response)
		if err != nil {
			return s.failJoin(row, err)
		}
		credentials := cluster.Credentials{CACertPEM: response.CACertPEM, CertPEM: response.CertPEM, KeyPEM: secrets.KeyPEM}
		_, _, identity, err := credentials.Load()
		if err != nil || identity.GUID != self.GUID || identity.Role != cluster.RoleSlave || response.Master != profile.Master || response.ResumeUntil <= time.Now().UnixMilli() {
			return s.failJoin(row, pairingError(400, "invalid_issued_pairing_identity"))
		}
		secrets.Credentials = credentials
		// Persist the dedicated full-admin key and the only recoverable plaintext
		// copy in one transaction; never rotate an existing user's API key.
		return pairingDB().Transaction(func(tx *gorm.DB) error {
			token, err := randomPairingSecret()
			if err != nil {
				return err
			}
			apiToken := model.ApiToken{Name: "cluster-pairing:" + row.ID, Token: panelcrypto.HashTokenSHA256(token), Enabled: true, Scope: model.ApiScopeAdmin}
			if err := tx.Create(&apiToken).Error; err != nil {
				return err
			}
			secrets.AdminToken = token
			payload, err := sealJoin(row.ID, secrets)
			if err != nil {
				return err
			}
			return tx.Model(row).Updates(map[string]any{"status": PairingIssued, "payload": payload, "admin_token_id": apiToken.Id, "deadline": response.ResumeUntil,
				"next_attempt_at": 0, "failures": 0, "attempts": row.Attempts + 1, "last_error": ""}).Error
		})
	case PairingIssued:
		if secrets.PublicIP == nil {
			probe := nodeip.Probe
			if s.probeIP != nil {
				probe = s.probeIP
			}
			report := probe(ctx)
			if report.IPv4 == "" && report.IPv6 == "" && (!row.Recovery || secrets.Request.Address == "") {
				return s.failJoin(row, pairingError(503, "pairing_public_ip_unavailable"))
			}
			port, err := (&SettingService{}).GetPort()
			if err != nil {
				return err
			}
			if override, configured, err := config.GetPortOverride(); configured && err == nil {
				port = override
			}
			secrets.PublicIP = &report
			if secrets.Request.Address == "" {
				secrets.Request.Address = report.IPv4
				if secrets.Request.Address == "" {
					secrets.Request.Address = report.IPv6
				}
			}
			secrets.PanelPort = port
			payload, err := sealJoin(row.ID, secrets)
			if err != nil {
				return err
			}
			if err := pairingDB().Model(row).Update("payload", payload).Error; err != nil {
				return err
			}
		}
		config, err := cluster.ClientTLS(secrets.Credentials, profile.Master)
		if err != nil {
			return s.failJoin(row, pairingError(400, "invalid_stored_pairing_credentials"))
		}
		var response cluster.PairingReceipt
		err = pairingRPC(ctx, config, secrets.Request.AllowPrivateMaster, pairingURL(profile.MasterAddress, profile.MasterPort, "/cluster/v1/pairings/"+profile.EnrollmentID+"/register"), "",
			cluster.RegisterRequest{Address: secrets.Request.Address, Port: secrets.Request.Port, BasePath: secrets.BasePath, AdminToken: secrets.AdminToken, PublicIP: secrets.PublicIP, PanelPort: secrets.PanelPort}, &response)
		if err != nil {
			return s.failJoin(row, err)
		}
		if response.Status == PairingProvisioning && response.NodeID == 0 {
			return pairingDB().Model(row).Updates(map[string]any{"next_attempt_at": time.Now().Add(2 * time.Second).UnixMilli(), "failures": 0, "last_error": "", "attempts": row.Attempts + 1}).Error
		}
		if response.NodeID <= 0 || (response.Status != PairingRegistered && response.Status != PairingCompleted) {
			return s.failJoin(row, pairingError(502, "invalid_pairing_receipt"))
		}
		// Pairing is committed by the master now. Install identity, trust and
		// role atomically; normal management stays blocked until this commit.
		controlSettingsMu.Lock()
		panelRoleMu.Lock()
		err = pairingDB().Transaction(func(tx *gorm.DB) error {
			var trustErr error
			if row.Recovery {
				trustErr = replacePeerTx(tx, profile.Master)
			} else {
				trustErr = trustPairingPeer(tx, profile.Master)
			}
			if trustErr != nil {
				return trustErr
			}
			// The role/CA cutover supersedes every rotation of the former identity.
			if err := writePKISetting(tx, settingControlRotation, identityRotation{}); err != nil {
				return err
			}
			if err := writePKISetting(tx, settingControlCAStage, caStage{}); err != nil {
				return err
			}
			material, err := json.Marshal(secrets.Credentials)
			if err != nil {
				return err
			}
			if err := putPairingSetting(tx, settingControlCredentials, string(material)); err != nil {
				return err
			}
			if err := putPairingSetting(tx, settingPanelRole, PanelRoleSlave); err != nil {
				return err
			}
			endpoint, err := json.Marshal(AccessLogMaster{GUID: profile.Master.GUID, Address: profile.MasterAddress, Port: profile.MasterPort, AllowPrivate: secrets.Request.AllowPrivateMaster})
			if err != nil {
				return err
			}
			if err := putPairingSetting(tx, settingAccessLogMaster, string(endpoint)); err != nil {
				return err
			}
			return tx.Model(row).Updates(map[string]any{"status": PairingConfirming, "node_id": response.NodeID, "next_attempt_at": 0,
				"failures": 0, "attempts": row.Attempts + 1, "last_error": ""}).Error
		})
		panelRoleMu.Unlock()
		controlSettingsMu.Unlock()
		if err != nil {
			return err
		}
		if hub := websocket.GetHub(); hub != nil {
			hub.SetClientsDisabled(true)
		}
		runtime.InvalidateMasterClientConnections()
		return nil
	case PairingConfirming:
		config, err := cluster.ClientTLS(secrets.Credentials, profile.Master)
		if err != nil {
			return err
		}
		var response cluster.PairingReceipt
		err = pairingRPC(ctx, config, secrets.Request.AllowPrivateMaster, pairingURL(profile.MasterAddress, profile.MasterPort, "/cluster/v1/pairings/"+profile.EnrollmentID+"/complete"), "", struct{}{}, &response)
		if err != nil {
			return s.failJoin(row, err)
		}
		if response.NodeID != row.NodeID || response.Status != PairingCompleted {
			return s.failJoin(row, pairingError(502, "invalid_pairing_receipt"))
		}
		return pairingDB().Model(row).Updates(map[string]any{"status": PairingCompleted, "active_slot": nil, "payload": "", "next_attempt_at": 0,
			"failures": 0, "attempts": row.Attempts + 1, "last_error": ""}).Error
	}
	return pairingError(409, "invalid_join_state")
}

func (s *PairingService) failJoin(row *model.NodeJoinJob, failure error) error {
	status := row.Status
	var pe *PairingError
	terminal := errors.As(failure, &pe) && pe.Status >= 400 && pe.Status < 500
	if terminal && status != PairingConfirming {
		if err := s.finishUncommittedJoin(row, PairingFailed, pairingFailureCode(failure)); err != nil {
			return err
		}
		return failure
	}
	failures := row.Failures + 1
	delay := time.Second << min(failures-1, 6)
	if delay > time.Minute {
		delay = time.Minute
	}
	updates := map[string]any{"status": status, "last_error": pairingFailureCode(failure), "attempts": row.Attempts + 1,
		"failures": failures, "next_attempt_at": time.Now().Add(delay).UnixMilli()}
	if err := pairingDB().Model(row).Where("active_slot IS NOT NULL").Updates(updates).Error; err != nil {
		return err
	}
	return failure
}

func (s *PairingService) finishUncommittedJoin(row *model.NodeJoinJob, status, code string) error {
	return pairingDB().Transaction(func(tx *gorm.DB) error {
		if row.AdminTokenID != 0 {
			if err := tx.Model(&model.ApiToken{}).Where("id = ? AND name = ? AND scope = ?", row.AdminTokenID, "cluster-pairing:"+row.ID, model.ApiScopeAdmin).Update("enabled", false).Error; err != nil {
				return err
			}
		}
		return tx.Model(row).Updates(map[string]any{"status": status, "active_slot": nil, "payload": "", "last_error": code, "attempts": row.Attempts + 1}).Error
	})
}

// RunPairingWorker discovers unfinished jobs after process restart. Its caller
// owns cancellation and waits for the returned channel before closing the DB.
func RunPairingWorker(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			var jobs []model.NodeJoinJob
			if err := pairingDB().WithContext(ctx).Where("active_slot IS NOT NULL AND next_attempt_at <= ?", time.Now().UnixMilli()).Find(&jobs).Error; err == nil {
				for _, job := range jobs {
					if ctx.Err() != nil {
						return
					}
					_ = (&PairingService{}).StepJoin(ctx, job.ID)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}
