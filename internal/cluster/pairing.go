package cluster

import (
	"github.com/mhsanaei/3x-ui/v3/internal/nodeip"
	"time"
)

const (
	EnrollmentTTL         = 15 * time.Minute
	EnrollmentResumeTTL   = 30 * time.Minute
	PairingRequestTimeout = 5 * time.Second
	// This ClientHello marker selects a staged identity for the probe only.
	// HTTP/1.1 is negotiated; existing control clients retain the active identity.
	PairingALPN      = "3x-ui-pairing-v1"
	PairingProbePath = "/cluster/v1/pairing/probe"
)

type PairingProfile struct {
	EnrollmentID  string `json:"enrollmentId"`
	MasterAddress string `json:"masterAddress"`
	MasterPort    int    `json:"masterPort"`
	Master        Peer   `json:"master"`
	Token         string `json:"token"`
	ExpiresAt     int64  `json:"expiresAt"`
	Recovery      bool   `json:"recovery,omitempty"`
	SlaveGUID     string `json:"slaveGuid,omitempty"`
}

type EnrollRequest struct {
	EnrollmentID      string `json:"enrollmentId"`
	GUID              string `json:"guid"`
	CSR               string `json:"csr"`
	RecoveryCert      string `json:"recoveryCert,omitempty"`
	RecoverySignature string `json:"recoverySignature,omitempty"`
}

type EnrollResponse struct {
	CertPEM     string `json:"certPem"`
	CACertPEM   string `json:"caCertPem"`
	Master      Peer   `json:"master"`
	ResumeUntil int64  `json:"resumeUntil"`
}

type RegisterRequest struct {
	Address    string         `json:"address"`
	Port       int            `json:"port"`
	BasePath   string         `json:"basePath"`
	AdminToken string         `json:"adminToken"`
	PublicIP   *nodeip.Report `json:"publicIp,omitempty"`
	PanelPort  int            `json:"panelPort,omitempty"`
}

type PairingReceipt struct {
	NodeID int    `json:"nodeId"`
	Status string `json:"status"`
}

type ProbeRequest struct {
	EnrollmentID string `json:"enrollmentId"`
	Challenge    string `json:"challenge"`
}

type ProbeResponse struct {
	GUID      string `json:"guid"`
	Role      string `json:"role"`
	Challenge string `json:"challenge"`
}
