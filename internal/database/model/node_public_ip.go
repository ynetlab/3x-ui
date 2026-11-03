package model

type NodePublicIP struct {
	NodeID        int    `gorm:"primaryKey" json:"nodeId"`
	NodeGUID      string `gorm:"size:36;index" json:"nodeGuid"`
	IPv4          string `gorm:"size:45" json:"ipv4"`
	IPv6          string `gorm:"size:45" json:"ipv6"`
	IPv4Available bool   `json:"ipv4Available"`
	IPv6Available bool   `json:"ipv6Available"`
	ObservedAt    int64  `json:"observedAt"`
	ReceivedAt    int64  `json:"receivedAt"`
}
