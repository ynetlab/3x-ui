package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/nodeip"
	"github.com/mhsanaei/3x-ui/v3/internal/util/netsafe"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	PairingPending      = "pending"
	PairingIssued       = "issued"
	PairingVerifying    = "verifying"
	PairingProvisioning = "provisioning"
	PairingRegistered   = "registered"
	PairingConfirming   = "confirming"
	PairingCompleted    = "completed"
	PairingExpired      = "expired"
	PairingFailed       = "failed"
)

var enrollmentMu sync.Mutex
var joinStepMu sync.Mutex

type PairingService struct {
	probeIP      func(context.Context) nodeip.Report
	certificates *NodeCertificateService
}

// PairingControlInfo exposes only the public identity used by generated commands.
type PairingControlInfo struct {
	Enabled bool         `json:"enabled"`
	Port    int          `json:"port"`
	Peer    cluster.Peer `json:"peer"`
}

func (s *PairingService) ControlInfo() (PairingControlInfo, error) {
	settings := &SettingService{}
	cfg, err := settings.GetControlConfig()
	if err != nil {
		return PairingControlInfo{}, err
	}
	credentials, err := settings.EnsureControlCredentials()
	if err != nil {
		return PairingControlInfo{}, err
	}
	peer, err := controlPeer(credentials)
	return PairingControlInfo{Enabled: cfg.Enabled, Port: cfg.Port, Peer: peer}, err
}

// Pairing rows may contain replayable tokens/private keys when the configured
// at-rest codec is off. Never interpolate their values into debug SQL logs.
func pairingDB() *gorm.DB {
	return database.GetDB().Session(&gorm.Session{Logger: logger.Discard})
}

type PairingView struct {
	ID                string `json:"id"`
	Name              string `json:"name,omitempty"`
	Status            string `json:"status"`
	GUID              string `json:"guid,omitempty"`
	NodeID            int    `json:"nodeId,omitempty"`
	ExistingNodeID    int    `json:"existingNodeId,omitempty"`
	ExpiresAt         int64  `json:"expiresAt"`
	ResumeUntil       int64  `json:"resumeUntil,omitempty"`
	Attempts          int    `json:"attempts,omitempty"`
	NextAttemptAt     int64  `json:"nextAttemptAt,omitempty"`
	LastError         string `json:"lastError,omitempty"`
	UpdatedAt         int64  `json:"updatedAt"`
	PrimaryDomain     string `json:"primaryDomain,omitempty"`
	CertificateStatus string `json:"certificateStatus,omitempty"`
}

type PairingError struct {
	Status int
	Code   string
}

func (e *PairingError) Error() string            { return e.Code }
func pairingError(status int, code string) error { return &PairingError{Status: status, Code: code} }

func randomPairingSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pairingHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func controlPeer(credentials cluster.Credentials) (cluster.Peer, error) {
	cert, _, id, err := credentials.Load()
	if err != nil {
		return cluster.Peer{}, err
	}
	return cluster.Peer{Identity: id, Fingerprint: cluster.Fingerprint(cert.Leaf), CertificateNotAfter: cert.Leaf.NotAfter.UnixMilli()}, nil
}

func (s *PairingService) enrollment(id string) (*model.NodeEnrollment, error) {
	var row model.NodeEnrollment
	if err := pairingDB().Where("id = ?", id).First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func (s *PairingService) join(id string) (*model.NodeJoinJob, error) {
	var row model.NodeJoinJob
	if err := pairingDB().Where("id = ?", id).First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func enrollmentView(row *model.NodeEnrollment) PairingView {
	status := row.Status
	now := time.Now().UnixMilli()
	if status == PairingPending && now >= row.ExpiresAt || (status == PairingIssued || status == PairingVerifying || status == PairingProvisioning) && now >= row.ResumeUntil {
		status = PairingExpired
	}
	return PairingView{ID: row.ID, Name: row.Name, Status: status, GUID: row.SlaveGUID, NodeID: row.NodeID, ExistingNodeID: row.ExistingNodeID,
		ExpiresAt: row.ExpiresAt, ResumeUntil: row.ResumeUntil, LastError: row.LastError, UpdatedAt: row.UpdatedAt, PrimaryDomain: row.PrimaryDomain}
}

func joinView(row *model.NodeJoinJob) PairingView {
	return PairingView{ID: row.ID, Status: row.Status, GUID: row.MasterGUID, NodeID: row.NodeID, ExpiresAt: row.Deadline,
		Attempts: row.Attempts, NextAttemptAt: row.NextAttemptAt, LastError: row.LastError, UpdatedAt: row.UpdatedAt}
}

func (s *PairingService) EnrollmentStatus(id string) (PairingView, error) {
	row, err := s.enrollment(id)
	if err != nil {
		return PairingView{}, err
	}
	view := enrollmentView(row)
	var job model.NodeCertificateJob
	if err := pairingDB().Where("enrollment_id = ?", id).Order("created_at DESC").First(&job).Error; err == nil {
		view.CertificateStatus = job.Status
		if job.LastError != "" {
			view.LastError = job.LastError
		}
	}
	return view, nil
}
func (s *PairingService) JoinStatus(id string) (PairingView, error) {
	row, err := s.join(id)
	if err != nil {
		return PairingView{}, err
	}
	return joinView(row), nil
}

func pairingURL(address string, port int, path string) string {
	return (&url.URL{Scheme: "https", Host: net.JoinHostPort(address, strconv.Itoa(port)), Path: path}).String()
}

// pairingRPC never follows redirects or includes tokens in URLs or errors.
func pairingRPC(ctx context.Context, config *tls.Config, allowPrivate bool, target, token string, body, output any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(netsafe.ContextWithAllowPrivate(ctx, allowPrivate), cluster.PairingRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(data))
	if err != nil {
		return pairingError(400, "invalid_pairing_address")
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	transport := &http.Transport{TLSClientConfig: config, DialContext: netsafe.SSRFGuardedDialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, cluster.ErrControlPeerMismatch) {
			return pairingError(401, "pairing_peer_identity_mismatch")
		}
		return pairingError(503, "pairing_peer_unreachable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return pairingError(response.StatusCode, "pairing_peer_rejected")
	}
	reader := io.LimitReader(response.Body, (4<<20)+1)
	raw, err := io.ReadAll(reader)
	if err != nil || len(raw) > 4<<20 {
		return pairingError(502, "invalid_pairing_response")
	}
	if err := json.Unmarshal(raw, output); err != nil {
		return pairingError(502, "invalid_pairing_response")
	}
	return nil
}

func putPairingSetting(tx *gorm.DB, key, value string) error {
	result := tx.Model(&model.Setting{}).Where("key = ?", key).Update("value", value)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return tx.Create(&model.Setting{Key: key, Value: value}).Error
	}
	return nil
}

func trustPairingPeer(tx *gorm.DB, peer cluster.Peer) error {
	if err := peer.Validate(); err != nil {
		return err
	}
	var row model.Setting
	var peers []cluster.Peer
	err := tx.Where("key = ?", settingControlPeers).First(&row).Error
	if err == nil {
		if err := json.Unmarshal([]byte(row.Value), &peers); err != nil {
			return err
		}
	} else if !database.IsNotFound(err) {
		return err
	}
	found := false
	for i, old := range peers {
		if err := old.Validate(); err != nil {
			return err
		}
		if old.GUID == peer.GUID {
			if old != peer {
				return pairingError(409, "pairing_peer_binding_conflict")
			}
			peers[i], found = peer, true
		} else if old.Role == cluster.RoleMaster && peer.Role == cluster.RoleMaster {
			return pairingError(409, "already_paired_to_another_master")
		}
	}
	if !found {
		peers = append(peers, peer)
	}
	data, err := json.Marshal(peers)
	if err != nil {
		return err
	}
	return putPairingSetting(tx, settingControlPeers, string(data))
}

func validPairingID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func normalizedPairingPath(path string) (string, error) {
	path = normalizeBasePath(path)
	if strings.ContainsAny(path, "?#\\\r\n") || strings.Contains(path, "..") || strings.Contains(path, "%") {
		return "", pairingError(400, "invalid_pairing_base_path")
	}
	return path, nil
}

func pairingFailureCode(err error) string {
	var pe *PairingError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return "pairing_storage_error"
}
