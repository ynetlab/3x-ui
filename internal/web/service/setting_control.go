package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	panelcrypto "github.com/mhsanaei/3x-ui/v3/internal/util/crypto"
)

const (
	settingControlConfig      = "controlConfig"
	settingControlCA          = "controlCA"
	settingControlCredentials = "controlCredentials"
	settingControlPeers       = "controlPeers"
)

var controlSettingsMu sync.Mutex

// ControlConfig is host configuration, intentionally absent from AllSetting.
type ControlConfig struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"`
	Port    int    `json:"port"`
}

func (c ControlConfig) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("control port must be between 1 and 65535")
	}
	if c.Listen != "" && net.ParseIP(c.Listen) == nil {
		return errors.New("control listen address must be an IP address")
	}
	return nil
}

func (s *SettingService) GetControlConfig() (ControlConfig, error) {
	value, err := s.getString(settingControlConfig)
	if err != nil {
		return ControlConfig{}, err
	}
	var config ControlConfig
	if err := json.Unmarshal([]byte(value), &config); err != nil {
		return config, fmt.Errorf("invalid control config: %w", err)
	}
	return config, config.Validate()
}

func (s *SettingService) SetControlConfig(config ControlConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	controlSettingsMu.Lock()
	defer controlSettingsMu.Unlock()
	return s.saveControlJSON(settingControlConfig, config)
}

func (s *SettingService) saveControlJSON(key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.saveSetting(key, string(data))
}

func (s *SettingService) ControlIdentity() (cluster.Identity, error) {
	role, err := s.GetPanelRole()
	if err != nil {
		return cluster.Identity{}, err
	}
	// Identity checks are on the request path. Read an existing GUID without
	// rewriting it (the legacy getter also persists its process default).
	guid := defaultValueMap["panelGuid"]
	row, err := s.getSetting("panelGuid")
	if database.IsNotFound(err) {
		if err := s.saveSetting("panelGuid", guid); err != nil {
			return cluster.Identity{}, err
		}
	} else if err != nil {
		return cluster.Identity{}, err
	} else {
		guid = row.Value
	}
	identity := cluster.Identity{GUID: guid, Role: role}
	return identity, identity.Validate()
}

// controlCALocked uses a separate trust root from legacy panel mTLS. A slave
// certificate must never acquire the legacy listener's node-sync authority.
// Both halves are persisted together in one settings row.
func (s *SettingService) controlCALocked() (panelcrypto.CertKeyPEM, error) {
	value, err := s.getString(settingControlCA)
	if err != nil {
		return panelcrypto.CertKeyPEM{}, err
	}
	if value != "" {
		var ca panelcrypto.CertKeyPEM
		if err := json.Unmarshal([]byte(value), &ca); err != nil {
			return ca, fmt.Errorf("invalid stored control CA: %w", err)
		}
		if len(ca.CertPEM) == 0 || len(ca.KeyPEM) == 0 {
			return ca, errors.New("stored control CA is incomplete; refusing to regenerate")
		}
		return ca, nil
	}
	ca, err := panelcrypto.GenerateNodeCAForYears("3x-ui control CA", 30)
	if err != nil {
		return ca, err
	}
	if err := s.saveControlJSON(settingControlCA, ca); err != nil {
		return panelcrypto.CertKeyPEM{}, err
	}
	return ca, nil
}

// IssueControlIdentity is a signing primitive, not an enrollment endpoint.
// Pairing must validate its one-time token before calling it. The requester
// retains its locally generated key; the CA private key never leaves here.
func (s *SettingService) IssueControlIdentity(csr []byte, identity cluster.Identity) ([]byte, string, error) {
	controlSettingsMu.Lock()
	defer controlSettingsMu.Unlock()
	role, err := s.GetPanelRole()
	if err != nil {
		return nil, "", err
	}
	if role != PanelRoleMaster {
		return nil, "", errors.New("only a master may issue control identities")
	}
	ca, err := s.controlCALocked()
	if err != nil {
		return nil, "", err
	}
	cert, err := cluster.IssueIdentity(ca, csr, identity)
	if err != nil {
		return nil, "", err
	}
	return cert, string(ca.CertPEM), nil
}

// EnsureControlCredentials creates credentials only for an unconfigured master.
// Slaves receive a signed identity from their master during pairing.
func (s *SettingService) EnsureControlCredentials() (cluster.Credentials, error) {
	controlSettingsMu.Lock()
	defer controlSettingsMu.Unlock()
	self, err := s.ControlIdentity()
	if err != nil {
		return cluster.Credentials{}, err
	}
	value, err := s.getString(settingControlCredentials)
	if err != nil {
		return cluster.Credentials{}, err
	}
	if value != "" {
		var credentials cluster.Credentials
		if err := json.Unmarshal([]byte(value), &credentials); err != nil {
			return credentials, fmt.Errorf("invalid control credentials: %w", err)
		}
		_, _, identity, err := credentials.Load()
		if err != nil {
			return credentials, err
		}
		if identity != self {
			return credentials, errors.New("stored control identity does not match this panel's GUID and role")
		}
		return credentials, nil
	}
	if self.Role != PanelRoleMaster {
		return cluster.Credentials{}, errors.New("slave has no control credentials; complete pairing before enabling its control listener")
	}
	ca, err := s.controlCALocked()
	if err != nil {
		return cluster.Credentials{}, err
	}
	csr, key, err := cluster.NewCSR()
	if err != nil {
		return cluster.Credentials{}, err
	}
	cert, err := cluster.IssueIdentity(ca, csr, self)
	if err != nil {
		return cluster.Credentials{}, err
	}
	credentials := cluster.Credentials{CACertPEM: string(ca.CertPEM), CertPEM: string(cert), KeyPEM: string(key)}
	if err := s.saveControlJSON(settingControlCredentials, credentials); err != nil {
		return cluster.Credentials{}, err
	}
	return credentials, nil
}

// SaveControlCredentials may stage a signed slave identity, but never changes
// the role or enables pairing. The active role must match at listener startup.
func (s *SettingService) SaveControlCredentials(credentials cluster.Credentials) error {
	_, _, identity, err := credentials.Load()
	if err != nil {
		return err
	}
	guid, err := s.GetPanelGuid()
	if err != nil {
		return err
	}
	if identity.GUID != guid {
		return errors.New("control credentials belong to another panel")
	}
	controlSettingsMu.Lock()
	defer controlSettingsMu.Unlock()
	return s.saveControlJSON(settingControlCredentials, credentials)
}

func (s *SettingService) controlPeersLocked() ([]cluster.Peer, error) {
	value, err := s.getString(settingControlPeers)
	if err != nil {
		return nil, err
	}
	var peers []cluster.Peer
	if err := json.Unmarshal([]byte(value), &peers); err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(peers))
	for _, peer := range peers {
		if err := peer.Validate(); err != nil {
			return nil, err
		}
		if seen[peer.GUID] {
			return nil, errors.New("duplicate control peer GUID")
		}
		seen[peer.GUID] = true
	}
	return peers, nil
}

func (s *SettingService) LookupControlPeer(ctx context.Context, guid string) (cluster.Peer, error) {
	if err := ctx.Err(); err != nil {
		return cluster.Peer{}, err
	}
	peers, err := s.controlPeersLocked()
	if err != nil {
		return cluster.Peer{}, err
	}
	for _, peer := range peers {
		if peer.GUID == guid {
			return peer, nil
		}
	}
	return cluster.Peer{}, cluster.ErrPeerNotTrusted
}

// TrustControlPeer binds the exact GUID, role and leaf pin. A trusted CA alone
// grants no HTTP authority. This method is internal to the pairing workflow.
func (s *SettingService) TrustControlPeer(peer cluster.Peer) error {
	if err := peer.Validate(); err != nil {
		return err
	}
	self, err := s.ControlIdentity()
	if err != nil {
		return err
	}
	if peer.GUID == self.GUID {
		return errors.New("cannot trust this panel as its own peer")
	}
	controlSettingsMu.Lock()
	defer controlSettingsMu.Unlock()
	peers, err := s.controlPeersLocked()
	if err != nil {
		return err
	}
	index := -1
	for i, existing := range peers {
		if existing.GUID == peer.GUID {
			index = i
		}
		if peer.Role == cluster.RoleMaster && existing.Role == cluster.RoleMaster && existing.GUID != peer.GUID {
			return errors.New("a slave can trust only one managing master")
		}
	}
	if index >= 0 {
		peers[index] = peer
	} else {
		peers = append(peers, peer)
	}
	return s.saveControlJSON(settingControlPeers, peers)
}

func (s *SettingService) RemoveControlPeer(guid string) error {
	controlSettingsMu.Lock()
	defer controlSettingsMu.Unlock()
	peers, err := s.controlPeersLocked()
	if err != nil {
		return err
	}
	filtered := make([]cluster.Peer, 0, len(peers))
	for _, peer := range peers {
		if peer.GUID != guid {
			filtered = append(filtered, peer)
		}
	}
	return s.saveControlJSON(settingControlPeers, filtered)
}

func (s *SettingService) ControlTLSForNode(node *model.Node) (*tls.Config, error) {
	if node.ControlRecoveryRequired {
		return nil, pairingError(409, "control_recovery_required")
	}
	self, err := s.ControlIdentity()
	if err != nil {
		return nil, err
	}
	if self.Role != cluster.RoleMaster {
		return nil, errors.New("only a master can manage paired nodes")
	}
	peer, err := s.LookupControlPeer(context.Background(), node.Guid)
	if err != nil {
		return nil, err
	}
	if peer.Role != cluster.RoleSlave || peer.Fingerprint != node.PinnedCertSha256 {
		return nil, errors.New("paired node trust binding changed")
	}
	credentials, err := outgoingControlCredentials(peer)
	if err != nil {
		return nil, err
	}
	return cluster.ClientTLS(credentials, peer)
}
