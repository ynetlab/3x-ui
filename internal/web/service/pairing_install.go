package service

import (
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

const settingSlaveInstallPairingID = "slaveInstallPairingId"

// PrepareSlaveInstall is a local installer operation, never an HTTP endpoint.
// It refuses existing panel data, except an identical installer task replay.
func (s *PairingService) PrepareSlaveInstall(req JoinPairingRequest) (PairingView, error) {
	view, err := s.startJoin(req, true)
	if err != nil {
		return view, err
	}
	if view.Status == PairingExpired || (view.Status == PairingPending || view.Status == PairingIssued) && view.ExpiresAt <= time.Now().UnixMilli() {
		return view, pairingError(410, "slave_install_pairing_expired_manual_recovery_required")
	}
	if view.Status == PairingFailed {
		return view, pairingError(409, "slave_install_pairing_failed_manual_recovery_required")
	}
	return view, nil
}

func (s *PairingService) ResumeSlaveInstall(req JoinPairingRequest) (PairingView, error) {
	id, err := (&SettingService{}).getString(settingSlaveInstallPairingID)
	if err != nil {
		return PairingView{}, err
	}
	if id == "" {
		return PairingView{}, pairingError(409, "new_slave_install_requires_empty_panel")
	}
	return s.PrepareSlaveInstall(req)
}

func (s *PairingService) requireFreshSlaveInstall() error {
	for _, table := range []any{&model.User{}, &model.Node{}, &model.Inbound{}, &model.ApiToken{}, &model.NodeJoinJob{}, &model.NodeEnrollment{}} {
		var count int64
		if err := pairingDB().Model(table).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return pairingError(409, "new_slave_install_requires_empty_panel")
		}
	}
	settings := &SettingService{}
	for _, key := range []string{settingControlCredentials, settingControlCA, settingSlaveInstallPairingID} {
		value, err := settings.getString(key)
		if err != nil {
			return err
		}
		if value != "" {
			return pairingError(409, "new_slave_install_requires_empty_panel")
		}
	}
	return nil
}

// IsPendingSlaveInstall permits a listener with no active certificate only for
// an installer-created slave. Every ordinary TLS handshake still fails closed;
// the staged identity can serve only the authenticated pairing proof.
func (s *PairingService) IsPendingSlaveInstall() (bool, error) {
	settings := &SettingService{}
	role, err := settings.GetPanelRole()
	if err != nil || role != PanelRoleSlave {
		return false, err
	}
	id, err := settings.getString(settingSlaveInstallPairingID)
	if err != nil || id == "" {
		return false, err
	}
	if !validPairingID(id) {
		return false, pairingError(500, "invalid_slave_install_state")
	}
	if _, err := s.join(id); err != nil {
		if database.IsNotFound(err) {
			return false, pairingError(500, "invalid_slave_install_state")
		}
		return false, err
	}
	value, err := settings.getString(settingControlCredentials)
	return value == "", err
}
