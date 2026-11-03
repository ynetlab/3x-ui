package service

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/panelcert"
	"gorm.io/gorm"
)

const settingPanelCertificateInstall = "panelCertificateInstall"
const certificateConfirmationWindow = 2 * time.Minute

var certificateInstallMu sync.Mutex
var panelCertificateReloader struct {
	sync.RWMutex
	apply    func(string, string) error
	snapshot func() func() error
}
var certificateRollbackID string
var certificateRollback func() error

// SetPanelCertificateReloader is owned by the panel listener lifecycle.
func SetPanelCertificateReloader(apply func(string, string) error, snapshot ...func() func() error) {
	panelCertificateReloader.Lock()
	panelCertificateReloader.apply = apply
	panelCertificateReloader.snapshot = nil
	if len(snapshot) > 0 {
		panelCertificateReloader.snapshot = snapshot[0]
	}
	panelCertificateReloader.Unlock()
}

func capturePanelCertificateRollback(id string) {
	if certificateRollbackID == id {
		return
	}
	panelCertificateReloader.RLock()
	defer panelCertificateReloader.RUnlock()
	certificateRollbackID = id
	certificateRollback = nil
	if panelCertificateReloader.snapshot != nil {
		certificateRollback = panelCertificateReloader.snapshot()
	}
}

func reloadPanelCertificate(certFile, keyFile string) error {
	panelCertificateReloader.RLock()
	defer panelCertificateReloader.RUnlock()
	if panelCertificateReloader.apply == nil {
		return errors.New("panel_certificate_reload_unavailable")
	}
	return panelCertificateReloader.apply(certFile, keyFile)
}

type certificateInstall struct {
	ID           string   `json:"id"`
	MasterGUID   string   `json:"masterGuid"`
	Fingerprint  string   `json:"fingerprint"`
	Domains      []string `json:"domains"`
	CertFile     string   `json:"certFile"`
	KeyFile      string   `json:"keyFile"`
	PreviousCert string   `json:"previousCert"`
	PreviousKey  string   `json:"previousKey"`
	Phase        string   `json:"phase"`
	Deadline     int64    `json:"deadline"`
}

type CertificateInstallRequest struct {
	ID           string            `json:"id"`
	EnrollmentID string            `json:"enrollmentId,omitempty"`
	Bundle       *panelcert.Bundle `json:"bundle,omitempty"`
}

type CertificateInstallReceipt struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Phase       string `json:"phase"`
	PanelPort   int    `json:"panelPort"`
}

func certificateInstallState() (certificateInstall, error) {
	var setting model.Setting
	err := pairingDB().Where("key = ?", settingPanelCertificateInstall).First(&setting).Error
	if database.IsNotFound(err) {
		return certificateInstall{}, nil
	}
	if err != nil {
		return certificateInstall{}, err
	}
	var state certificateInstall
	err = json.Unmarshal([]byte(setting.Value), &state)
	return state, err
}

func saveCertificateInstall(tx *gorm.DB, state certificateInstall) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return putPairingSetting(tx, settingPanelCertificateInstall, string(data))
}

func writeCertificateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		previous, readErr := os.ReadFile(path)
		if readErr == nil && string(previous) == string(data) {
			return nil
		}
		return errors.New("panel_certificate_file_conflict")
	}
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	return closeErr
}

func rollbackCertificateInstall(state *certificateInstall) error {
	if state.Phase != "active" && state.Phase != "staged" {
		return nil
	}
	var err error
	if certificateRollbackID == state.ID && certificateRollback != nil {
		err = certificateRollback()
	} else {
		err = reloadPanelCertificate(state.PreviousCert, state.PreviousKey)
	}
	if err != nil {
		return err
	}
	certificateRollbackID, certificateRollback = "", nil
	state.Phase = "rolled_back"
	return saveCertificateInstall(pairingDB(), *state)
}

// installCertificate is called only behind bound-master or enrollment-scoped
// mTLS plus the full admin key. roots is nil outside isolated tests.
func installCertificate(master string, operation string, req CertificateInstallRequest, roots *x509.CertPool) (CertificateInstallReceipt, error) {
	certificateInstallMu.Lock()
	defer certificateInstallMu.Unlock()
	if !validPairingID(req.ID) {
		return CertificateInstallReceipt{}, pairingError(400, "invalid_certificate_request")
	}
	state, err := certificateInstallState()
	if err != nil {
		return CertificateInstallReceipt{}, err
	}
	if (state.Phase == "active" || state.Phase == "staged") && state.Deadline <= time.Now().UnixMilli() {
		if err := rollbackCertificateInstall(&state); err != nil {
			return CertificateInstallReceipt{}, err
		}
	}
	if operation == "stage" {
		if req.Bundle == nil {
			return CertificateInstallReceipt{}, pairingError(400, "invalid_certificate_request")
		}
		pair, err := req.Bundle.Validate(time.Now(), roots)
		if err != nil {
			return CertificateInstallReceipt{}, pairingError(400, "invalid_panel_certificate")
		}
		fingerprint := panelcert.Fingerprint(pair.Leaf)
		if state.ID == req.ID && (state.Fingerprint != fingerprint || state.MasterGUID != master) {
			return CertificateInstallReceipt{}, pairingError(409, "certificate_job_changed")
		}
		if state.ID != req.ID && (state.Phase == "active" || state.Phase == "staged") {
			return CertificateInstallReceipt{}, pairingError(409, "certificate_install_busy")
		}
		if state.ID != req.ID || state.Phase == "rolled_back" {
			cert, err := (&SettingService{}).GetCertFile()
			if err != nil {
				return CertificateInstallReceipt{}, err
			}
			key, err := (&SettingService{}).GetKeyFile()
			if err != nil {
				return CertificateInstallReceipt{}, err
			}
			dir := filepath.Join(config.GetDBFolderPath(), "panel-certificates", req.ID)
			if err := os.MkdirAll(dir, 0700); err != nil {
				return CertificateInstallReceipt{}, err
			}
			certFile, keyFile := filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "private-key.pem")
			if err := writeCertificateFile(certFile, []byte(req.Bundle.Certificate)); err != nil {
				return CertificateInstallReceipt{}, err
			}
			if err := writeCertificateFile(keyFile, []byte(req.Bundle.PrivateKey)); err != nil {
				return CertificateInstallReceipt{}, err
			}
			state = certificateInstall{ID: req.ID, MasterGUID: master, Fingerprint: fingerprint, Domains: req.Bundle.Domains, CertFile: certFile, KeyFile: keyFile, PreviousCert: cert, PreviousKey: key, Phase: "staged", Deadline: time.Now().Add(certificateConfirmationWindow).UnixMilli()}
			if err := saveCertificateInstall(pairingDB(), state); err != nil {
				return CertificateInstallReceipt{}, err
			}
		}
	} else {
		if state.ID != req.ID || state.MasterGUID != master {
			return CertificateInstallReceipt{}, pairingError(409, "certificate_install_not_staged")
		}
		switch operation {
		case "activate":
			if state.Phase == "committed" {
				break
			}
			if state.Phase != "staged" && state.Phase != "active" {
				return CertificateInstallReceipt{}, pairingError(409, "certificate_install_not_staged")
			}
			cert, err := os.ReadFile(state.CertFile)
			if err != nil {
				return CertificateInstallReceipt{}, err
			}
			key, err := os.ReadFile(state.KeyFile)
			if err != nil {
				return CertificateInstallReceipt{}, err
			}
			bundle := panelcert.Bundle{Certificate: string(cert), PrivateKey: string(key), Domains: state.Domains}
			if _, err := bundle.Validate(time.Now(), roots); err != nil {
				return CertificateInstallReceipt{}, err
			}
			capturePanelCertificateRollback(state.ID)
			state.Phase = "active"
			if err := saveCertificateInstall(pairingDB(), state); err != nil {
				return CertificateInstallReceipt{}, err
			}
			if err := reloadPanelCertificate(state.CertFile, state.KeyFile); err != nil {
				_ = rollbackCertificateInstall(&state)
				return CertificateInstallReceipt{}, err
			}
		case "confirm":
			if state.Phase == "committed" {
				break
			}
			if state.Phase != "active" {
				return CertificateInstallReceipt{}, pairingError(409, "certificate_install_not_active")
			}
			state.Phase = "committed"
			if err := pairingDB().Transaction(func(tx *gorm.DB) error {
				if err := putPairingSetting(tx, "webCertFile", state.CertFile); err != nil {
					return err
				}
				if err := putPairingSetting(tx, "webKeyFile", state.KeyFile); err != nil {
					return err
				}
				return saveCertificateInstall(tx, state)
			}); err != nil {
				return CertificateInstallReceipt{}, err
			}
			certificateRollbackID, certificateRollback = "", nil
		case "rollback":
			if err := rollbackCertificateInstall(&state); err != nil {
				return CertificateInstallReceipt{}, err
			}
		case "status":
		default:
			return CertificateInstallReceipt{}, pairingError(400, "invalid_certificate_operation")
		}
	}
	port, err := (&SettingService{}).GetPort()
	if err != nil {
		return CertificateInstallReceipt{}, err
	}
	if override, configured, err := config.GetPortOverride(); configured && err == nil {
		port = override
	}
	return CertificateInstallReceipt{ID: state.ID, Fingerprint: state.Fingerprint, Phase: state.Phase, PanelPort: port}, nil
}

func recoverCertificateInstall(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	certificateInstallMu.Lock()
	defer certificateInstallMu.Unlock()
	state, err := certificateInstallState()
	if err == nil && (state.Phase == "staged" || state.Phase == "active") && state.Deadline <= time.Now().UnixMilli() {
		_ = rollbackCertificateInstall(&state)
	}
}

// Settings still point at the confirmed previous files until confirm commits.
// A process restart therefore rolls back an interrupted activation naturally.
func RecoverPanelCertificateStartup() error {
	certificateInstallMu.Lock()
	defer certificateInstallMu.Unlock()
	certificateRollbackID, certificateRollback = "", nil
	state, err := certificateInstallState()
	if err != nil {
		return err
	}
	if state.Phase == "active" || state.Phase == "staged" {
		state.Phase = "rolled_back"
		return saveCertificateInstall(pairingDB(), state)
	}
	return nil
}
