package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/crypto/nodetoken"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/web/runtime"
	"gorm.io/gorm"
)

const settingControlRotation = "controlIdentityRotation"
const settingControlCAStage = "controlCAStage"
const identityCheckInterval = 12 * time.Hour
const identityRenewBefore = 90 * 24 * time.Hour

var controlPKIMu sync.Mutex

type identityRotation struct {
	Previous      cluster.Credentials `json:"previous"`
	PreviousUntil int64               `json:"previousUntil"`
	ID            string              `json:"id"`
	CSR           string              `json:"csr"`
	Key           string              `json:"key"`
	Phase         string              `json:"phase"`
	NextCheck     int64               `json:"nextCheck"`
	Failures      int                 `json:"failures"`
	LastError     string              `json:"lastError"`
}

// Private rotation material is host-bound and never part of panel settings DTOs.
func readPKISetting(key string, value any) error {
	row, err := (&SettingService{}).getSetting(key)
	if database.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	guid, err := (&SettingService{}).ControlIdentity()
	if err != nil {
		return err
	}
	data, err := nodetoken.DecryptBound([]byte("control-pki/"+guid.GUID+"/"+key), row.Value)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(data), value)
}
func writePKISetting(tx *gorm.DB, key string, value any) error {
	var guidRow model.Setting
	if err := tx.Where("key = ?", "panelGuid").First(&guidRow).Error; err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	sealed, err := nodetoken.EncryptBound([]byte("control-pki/"+guidRow.Value+"/"+key), string(data))
	if err != nil {
		return err
	}
	return putPairingSetting(tx, key, sealed)
}
func saveRotation(state identityRotation) error {
	return writePKISetting(pairingDB(), settingControlRotation, state)
}
func replacePeerTx(tx *gorm.DB, peer cluster.Peer) error {
	if err := peer.Validate(); err != nil {
		return err
	}
	var row model.Setting
	if err := tx.Where("key = ?", settingControlPeers).First(&row).Error; err != nil {
		return err
	}
	var peers []cluster.Peer
	if err := json.Unmarshal([]byte(row.Value), &peers); err != nil {
		return err
	}
	found := false
	for i := range peers {
		if peers[i].GUID == peer.GUID {
			if peers[i].Role != peer.Role {
				return cluster.ErrPeerNotTrusted
			}
			peers[i] = peer
			found = true
		}
	}
	if !found {
		return cluster.ErrPeerNotTrusted
	}
	data, _ := json.Marshal(peers)
	return putPairingSetting(tx, settingControlPeers, string(data))
}
func storeCredentialsTx(tx *gorm.DB, c cluster.Credentials) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return putPairingSetting(tx, settingControlCredentials, string(data))
}

func (s *SettingService) controlServerCredentials(protocols []string) (cluster.Credentials, error) {
	requested := ""
	for _, p := range protocols {
		if strings.HasPrefix(p, cluster.ControlPinALPNPrefix) {
			requested = strings.TrimPrefix(p, cluster.ControlPinALPNPrefix)
			break
		}
	}
	active, err := s.EnsureControlCredentials()
	if err == nil {
		peer, e := controlPeer(active)
		if e == nil && (requested == "" || peer.Fingerprint == requested) {
			return active, nil
		}
	}
	if requested != "" {
		var state identityRotation
		if e := readPKISetting(settingControlRotation, &state); e == nil && time.Now().UnixMilli() < state.PreviousUntil {
			if peer, e := controlPeer(state.Previous); e == nil && peer.Fingerprint == requested {
				return state.Previous, nil
			}
		}
		var stage caStage
		if e := readPKISetting(settingControlCAStage, &stage); e == nil && !stage.Done && stage.Deadline > time.Now().UnixMilli() {
			if peer, e := controlPeer(stage.Credentials); e == nil && peer.Fingerprint == requested {
				return stage.Credentials, nil
			}
		}
	}
	if err != nil {
		return cluster.Credentials{}, err
	}
	return cluster.Credentials{}, cluster.ErrPeerNotTrusted
}

func outgoingControlCredentials(peer cluster.Peer) (cluster.Credentials, error) {
	active, err := (&SettingService{}).EnsureControlCredentials()
	if err != nil {
		return active, err
	}
	own, err := controlPeer(active)
	if err != nil {
		return active, err
	}
	if own.Role == cluster.RoleMaster && peer.AcknowledgedLocalFingerprint != own.Fingerprint {
		var state identityRotation
		if err := readPKISetting(settingControlRotation, &state); err != nil {
			return active, err
		}
		if state.PreviousUntil > time.Now().UnixMilli() && state.Previous.CertPEM != "" {
			return state.Previous, nil
		}
	}
	return active, nil
}

type identitySyncRequest struct {
	KnownMaster string `json:"knownMaster"`
}
type identitySyncResponse struct {
	CertPEM   string `json:"certPem"`
	CACertPEM string `json:"caCertPem"`
}
type identityRenewRequest struct {
	ID  string `json:"id"`
	CSR string `json:"csr"`
}
type identityRenewResponse struct {
	CertPEM string `json:"certPem"`
}

func registerIdentityControlRoutes(router *cluster.Router) {
	for _, op := range []string{"sync", "renew", "commit"} {
		operation := op
		router.HandleSlave("POST /cluster/v1/control-pki/"+op, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			controlPKIMu.Lock()
			defer controlPKIMu.Unlock()
			identity, ok := cluster.AuthenticatedPeer(r.Context())
			if !ok {
				pairingJSON(w, nil, cluster.ErrPeerNotTrusted)
				return
			}
			var node model.Node
			if err := pairingDB().Where("guid = ? AND control_connection = ? AND control_recovery_required = ?", identity.GUID, true, false).First(&node).Error; err != nil {
				pairingJSON(w, nil, pairingError(403, "control_recovery_required"))
				return
			}
			settings := &SettingService{}
			peer, err := settings.LookupControlPeer(r.Context(), identity.GUID)
			if err != nil {
				pairingJSON(w, nil, err)
				return
			}
			if operation == "sync" {
				var req identitySyncRequest
				if err := readPairingJSON(w, r, &req); err != nil {
					pairingJSON(w, nil, err)
					return
				}
				own, e := settings.EnsureControlCredentials()
				if e != nil {
					pairingJSON(w, nil, e)
					return
				}
				ownPeer, e := controlPeer(own)
				if e != nil {
					pairingJSON(w, nil, e)
					return
				}
				if req.KnownMaster == ownPeer.Fingerprint {
					changed := peer.AcknowledgedLocalFingerprint != ownPeer.Fingerprint
					peer.AcknowledgedLocalFingerprint = ownPeer.Fingerprint
					controlSettingsMu.Lock()
					err = replacePeerTx(pairingDB(), peer)
					controlSettingsMu.Unlock()
					if err == nil && changed {
						invalidateControlNode(node.Id)
					}
				}
				pairingJSON(w, identitySyncResponse{CertPEM: own.CertPEM, CACertPEM: own.CACertPEM}, err)
				return
			}
			var req identityRenewRequest
			if err := readPairingJSON(w, r, &req); err != nil {
				pairingJSON(w, nil, err)
				return
			}
			if !validPairingID(req.ID) {
				pairingJSON(w, nil, pairingError(400, "invalid_identity_renewal"))
				return
			}
			controlSettingsMu.Lock()
			defer controlSettingsMu.Unlock()
			var row model.ControlIdentityRenewal
			err = pairingDB().First(&row, "id = ?", req.ID).Error
			if database.IsNotFound(err) && operation == "renew" {
				if cluster.Fingerprint(r.TLS.PeerCertificates[0]) != peer.Fingerprint {
					pairingJSON(w, nil, pairingError(403, "identity_renewal_current_key_required"))
					return
				}
				ca, e := settings.controlCALocked()
				if e != nil {
					pairingJSON(w, nil, e)
					return
				}
				cert, e := cluster.IssueIdentity(ca, []byte(req.CSR), identity)
				if e != nil {
					pairingJSON(w, nil, pairingError(400, "invalid_identity_csr"))
					return
				}
				next, leaf, e := cluster.ValidateIdentityCertificate(string(cert), string(ca.CertPEM), identity)
				if e != nil {
					pairingJSON(w, nil, e)
					return
				}
				if leaf.NotAfter.Before(time.Now().AddDate(3, 0, -1)) {
					pairingJSON(w, nil, pairingError(503, "control_ca_rotation_required"))
					return
				}
				old := r.TLS.PeerCertificates[0]
				peer.PendingFingerprint = next.Fingerprint
				peer.PendingUntil = old.NotAfter.UnixMilli()
				row = model.ControlIdentityRenewal{ID: req.ID, ActiveGUID: &identity.GUID, GUID: identity.GUID, OldFingerprint: cluster.Fingerprint(old), CSRHash: pairingHash(req.CSR), CertPEM: string(cert), Status: "issued", ExpiresAt: old.NotAfter.UnixMilli()}
				err = pairingDB().Transaction(func(tx *gorm.DB) error {
					if e := tx.Model(&model.ControlIdentityRenewal{}).Where("guid = ? AND expires_at <= ?", identity.GUID, time.Now().UnixMilli()).Update("active_guid", nil).Error; e != nil {
						return e
					}
					if e := tx.Create(&row).Error; e != nil {
						return e
					}
					return replacePeerTx(tx, peer)
				})
			}
			if err != nil {
				pairingJSON(w, nil, err)
				return
			}
			if row.GUID != identity.GUID || (operation == "renew" && row.CSRHash != pairingHash(req.CSR)) {
				pairingJSON(w, nil, pairingError(409, "identity_renewal_changed"))
				return
			}
			if operation == "commit" {
				next, e := cluster.PeerFromPEM(row.CertPEM)
				if e != nil {
					pairingJSON(w, nil, e)
					return
				}
				if cluster.Fingerprint(r.TLS.PeerCertificates[0]) != next.Fingerprint {
					pairingJSON(w, nil, pairingError(403, "identity_renewal_proof_required"))
					return
				}
				if row.Status != "completed" {
					if peer.PendingFingerprint != next.Fingerprint || row.ExpiresAt <= time.Now().UnixMilli() {
						pairingJSON(w, nil, pairingError(409, "identity_renewal_expired"))
						return
					}
					next.PreviousFingerprint = row.OldFingerprint
					next.PreviousUntil = row.ExpiresAt
					next.AcknowledgedLocalFingerprint = peer.AcknowledgedLocalFingerprint
					err = pairingDB().Transaction(func(tx *gorm.DB) error {
						if e := replacePeerTx(tx, next); e != nil {
							return e
						}
						if e := tx.Model(&node).Update("pinned_cert_sha256", next.Fingerprint).Error; e != nil {
							return e
						}
						return tx.Model(&row).Updates(map[string]any{"status": "completed", "active_guid": nil}).Error
					})
					invalidateControlNode(node.Id)
				}
			}
			pairingJSON(w, identityRenewResponse{CertPEM: row.CertPEM}, err)
		}))
	}
}

func invalidateControlNode(id int) {
	runtime.InvalidateMasterClientConnections()
	if m := runtime.GetManager(); m != nil {
		m.InvalidateNode(id)
	}
}

func renewMasterIdentity() error {
	enrollmentMu.Lock()
	defer enrollmentMu.Unlock()
	var active int64
	now := time.Now().UnixMilli()
	if err := pairingDB().Model(&model.NodeEnrollment{}).Where("(status = ? AND expires_at > ?) OR (status IN ? AND resume_until > ?)", PairingPending, now, []string{PairingIssued, PairingVerifying, PairingProvisioning}, now).Count(&active).Error; err != nil {
		return err
	}
	if active > 0 {
		return pairingError(503, "control_pairing_in_progress")
	}
	settings := &SettingService{}
	old, err := settings.EnsureControlCredentials()
	if err != nil {
		return err
	}
	leaf, _, self, err := old.Load()
	if err != nil {
		return err
	}
	controlSettingsMu.Lock()
	defer controlSettingsMu.Unlock()
	ca, err := settings.controlCALocked()
	if err != nil {
		return err
	}
	csr, key, err := cluster.NewCSR()
	if err != nil {
		return err
	}
	cert, err := cluster.IssueIdentity(ca, csr, self)
	if err != nil {
		return err
	}
	next := cluster.Credentials{CACertPEM: old.CACertPEM, CertPEM: string(cert), KeyPEM: string(key)}
	issued, _, _, err := next.Load()
	if err != nil {
		return err
	}
	if issued.Leaf.NotAfter.Before(time.Now().AddDate(3, 0, -1)) {
		return pairingError(503, "control_ca_rotation_required")
	}
	state := identityRotation{Previous: old, PreviousUntil: leaf.Leaf.NotAfter.UnixMilli(), NextCheck: time.Now().Add(identityCheckInterval).UnixMilli()}
	err = pairingDB().Transaction(func(tx *gorm.DB) error {
		if e := storeCredentialsTx(tx, next); e != nil {
			return e
		}
		return writePKISetting(tx, settingControlRotation, state)
	})
	runtime.InvalidateMasterClientConnections()
	return err
}

func syncSlaveIdentity(ctx context.Context, state *identityRotation) error {
	settings := &SettingService{}
	var target AccessLogMaster
	row, err := settings.getSetting(settingAccessLogMaster)
	if err != nil {
		return err
	}
	if err = json.Unmarshal([]byte(row.Value), &target); err != nil {
		return err
	}
	peer, err := settings.LookupControlPeer(ctx, target.GUID)
	if err != nil {
		return err
	}
	active, err := settings.EnsureControlCredentials()
	if err != nil {
		return err
	}
	rpc := func(op string, body, out any) error {
		cfg, e := cluster.ClientTLS(active, peer)
		if e != nil {
			return e
		}
		return pairingRPC(ctx, cfg, target.AllowPrivate, pairingURL(target.Address, target.Port, "/cluster/v1/control-pki/"+op), "", body, out)
	}
	var synced identitySyncResponse
	if err = rpc("sync", identitySyncRequest{KnownMaster: peer.Fingerprint}, &synced); err != nil {
		return err
	}
	if synced.CACertPEM != active.CACertPEM {
		return errors.New("control_ca_changed_requires_recovery")
	}
	nextMaster, _, err := cluster.ValidateIdentityCertificate(synced.CertPEM, active.CACertPEM, peer.Identity)
	if err != nil {
		return err
	}
	if nextMaster.Fingerprint != peer.Fingerprint {
		nextMaster.PreviousFingerprint = peer.Fingerprint
		nextMaster.PreviousUntil = peer.CertificateNotAfter
		if nextMaster.PreviousUntil <= time.Now().UnixMilli() {
			return errors.New("control_master_identity_expired")
		}
		controlSettingsMu.Lock()
		err = replacePeerTx(pairingDB(), nextMaster)
		controlSettingsMu.Unlock()
		if err != nil {
			return err
		}
		peer = nextMaster
		if err = rpc("sync", identitySyncRequest{KnownMaster: peer.Fingerprint}, &synced); err != nil {
			return err
		}
	}
	leaf, _, _, err := active.Load()
	if err != nil {
		return err
	}
	if state.ID == "" && time.Until(leaf.Leaf.NotAfter) > identityRenewBefore {
		return nil
	}
	if state.ID == "" {
		csr, key, e := cluster.NewCSR()
		if e != nil {
			return e
		}
		state.ID = uuid.NewString()
		state.CSR = string(csr)
		state.Key = string(key)
		state.Phase = "issued"
		if err := saveRotation(*state); err != nil {
			return err
		}
	}
	if state.Phase == "issued" {
		var reply identityRenewResponse
		if err = rpc("renew", identityRenewRequest{ID: state.ID, CSR: state.CSR}, &reply); err != nil {
			return err
		}
		renewed := cluster.Credentials{CACertPEM: active.CACertPEM, CertPEM: reply.CertPEM, KeyPEM: state.Key}
		_, _, self, e := renewed.Load()
		if e != nil {
			return e
		}
		identity, e := settings.ControlIdentity()
		if e != nil || identity != self {
			return errors.New("control_identity_changed")
		}
		state.Previous = active
		state.PreviousUntil = leaf.Leaf.NotAfter.UnixMilli()
		state.Phase = "commit"
		controlSettingsMu.Lock()
		err = pairingDB().Transaction(func(tx *gorm.DB) error {
			if e := storeCredentialsTx(tx, renewed); e != nil {
				return e
			}
			return writePKISetting(tx, settingControlRotation, state)
		})
		controlSettingsMu.Unlock()
		if err != nil {
			return err
		}
		active = renewed
	}
	var reply identityRenewResponse
	if err = rpc("commit", identityRenewRequest{ID: state.ID}, &reply); err != nil {
		return err
	}
	state.ID = ""
	state.CSR = ""
	state.Key = ""
	state.Phase = ""
	return nil
}

func stepControlIdentity(ctx context.Context) error {
	controlPKIMu.Lock()
	defer controlPKIMu.Unlock()
	var state identityRotation
	if err := readPKISetting(settingControlRotation, &state); err != nil {
		return err
	}
	if state.NextCheck > time.Now().UnixMilli() {
		return nil
	}
	var stage caStage
	if err := readPKISetting(settingControlCAStage, &stage); err != nil {
		return err
	}
	if stage.ID != "" && !stage.Done && stage.Deadline > time.Now().UnixMilli() {
		return nil
	}
	settings := &SettingService{}
	active, err := settings.EnsureControlCredentials()
	if err != nil {
		return err
	}
	leaf, _, self, err := active.Load()
	if err != nil {
		return err
	}
	if self.Role == cluster.RoleMaster {
		if err = expireControlPeers(); err != nil {
			return err
		}
		if time.Until(leaf.Leaf.NotAfter) <= identityRenewBefore {
			err = renewMasterIdentity()
			if err == nil {
				return nil
			}
		}
	} else if self.Role == cluster.RoleSlave {
		err = syncSlaveIdentity(ctx, &state)
	}
	if state.PreviousUntil <= time.Now().UnixMilli() {
		state.Previous = cluster.Credentials{}
		state.PreviousUntil = 0
	}
	if err != nil {
		state.Failures++
		state.LastError = pairingFailureCode(err)
		state.NextCheck = time.Now().Add(min(time.Second<<min(state.Failures-1, 6), time.Minute)).UnixMilli()
	} else {
		state.Failures = 0
		state.LastError = ""
		state.NextCheck = time.Now().Add(identityCheckInterval).UnixMilli()
	}
	if e := saveRotation(state); e != nil {
		return e
	}
	return err
}

func RunControlPKIWorker(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			_ = stepControlIdentity(ctx)
			_ = stepCAChange(ctx)
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	return done
}
