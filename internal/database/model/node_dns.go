package model

// NodeDNSBinding keeps ownership and the last explicitly managed record. Zone
// and record IDs scope ownership; changing global credentials does not retarget
// existing bindings. No remote deletion is triggered by deleting a Node.
type NodeDNSBinding struct {
	ID            int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	NodeID        int    `gorm:"index:idx_node_dns_owner,priority:1" json:"nodeId"`
	NodeGUID      string `gorm:"size:36;index:idx_node_dns_owner,priority:2" json:"nodeGuid"`
	ZoneID        string `gorm:"size:32;uniqueIndex:idx_node_dns_record,priority:1;index:idx_node_dns_owner,priority:3" json:"zoneId"`
	RecordID      string `gorm:"size:32;uniqueIndex:idx_node_dns_record,priority:2" json:"recordId"`
	Name          string `gorm:"size:253" json:"name"`
	Type          string `gorm:"size:4" json:"type"`
	Content       string `gorm:"size:45" json:"content"`
	TTL           int    `json:"ttl"`
	Proxied       bool   `json:"proxied"`
	LastSyncError string `gorm:"size:96" json:"lastSyncError"`
	LastSyncedAt  int64  `json:"lastSyncedAt"`
	CreatedAt     int64  `gorm:"autoCreateTime:milli" json:"createdAt"`
	UpdatedAt     int64  `gorm:"autoUpdateTime:milli" json:"updatedAt"`
}
