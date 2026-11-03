package model

// AccessLog is the master archive. Event IDs are stable across cursor replay,
// process restart and acknowledgement loss, scoped to the authenticated source.
type AccessLog struct {
	ID         int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	NodeGUID   string `gorm:"size:36;uniqueIndex:idx_access_event,priority:1;index:idx_access_node_time,priority:1" json:"nodeGuid"`
	EventID    string `gorm:"size:64;uniqueIndex:idx_access_event,priority:2" json:"eventId"`
	OccurredAt int64  `gorm:"index;index:idx_access_node_time,priority:2" json:"occurredAt"`
	ReceivedAt int64  `gorm:"index" json:"receivedAt"`
	Source     string `json:"source"`
	Target     string `json:"target"`
	SourceIP   string `gorm:"size:45;index" json:"sourceIp"`
	TargetHost string `json:"targetHost"`
	TargetPort int    `json:"targetPort"`
	Network    string `gorm:"size:8" json:"network"`
	Email      string `json:"email"`
	Inbound    string `json:"inbound"`
	Outbound   string `json:"outbound"`
	Category   string `gorm:"size:16;index" json:"category"`
}

// AccessLogReceipt binds a batch to its exact body for idempotent acknowledgement.
type AccessLogReceipt struct {
	NodeGUID   string `gorm:"primaryKey;size:36" json:"-"`
	BatchID    string `gorm:"primaryKey;size:36" json:"-"`
	Digest     string `gorm:"size:64" json:"-"`
	Count      int    `json:"-"`
	ReceivedAt int64  `gorm:"index" json:"-"`
}
