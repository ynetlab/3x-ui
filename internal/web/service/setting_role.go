package service

import (
	"fmt"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/web/websocket"
)

var panelRoleMu sync.Mutex

const (
	PanelRoleMaster  = "master"
	PanelRoleSlave   = "slave"
	settingPanelRole = "panelRole"
)

// GetPanelRole gets its default from defaultValueMap when no role is stored. The role
// stays out of AllSetting so ordinary settings saves cannot switch a machine.
func (s *SettingService) GetPanelRole() (string, error) {
	role, err := s.getString(settingPanelRole)
	if err != nil {
		return "", err
	}
	if role != PanelRoleMaster && role != PanelRoleSlave {
		return "", fmt.Errorf("invalid panel role %q", role)
	}
	return role, nil
}

// SetPanelRole persists an explicit role change. Existing installations must
// only be switched to slave by a successful pairing flow; startup and ordinary
// settings updates never call this method. Pairing is implemented separately.
func (s *SettingService) SetPanelRole(role string) error {
	if role != PanelRoleMaster && role != PanelRoleSlave {
		return fmt.Errorf("panel role must be master or slave")
	}
	panelRoleMu.Lock()
	defer panelRoleMu.Unlock()
	if err := s.setString(settingPanelRole, role); err != nil {
		return err
	}
	if hub := websocket.GetHub(); hub != nil {
		hub.SetClientsDisabled(role == PanelRoleSlave)
	}
	return nil
}
