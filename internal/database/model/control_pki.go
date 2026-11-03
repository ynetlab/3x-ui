package model

// ControlIdentityRenewal stores public, idempotent issuance replies. Private
// identity keys are generated and retained exclusively by their owning panel.
type ControlIdentityRenewal struct {
	ID             string  `gorm:"primaryKey;size:36" json:"-"`
	ActiveGUID     *string `gorm:"uniqueIndex;size:36" json:"-"`
	GUID           string  `gorm:"index;size:36" json:"-"`
	OldFingerprint string  `json:"-"`
	CSRHash        string  `json:"-"`
	CertPEM        string  `json:"-"`
	Status         string  `gorm:"size:24" json:"-"`
	ExpiresAt      int64   `json:"-"`
	CreatedAt      int64   `gorm:"autoCreateTime:milli" json:"-"`
}

// ControlCAChange is an emergency revocation job. Payload retains old leaf
// credentials for bounded, pin-verified migration only, never the old CA key.
type ControlCAChange struct {
	ID            string  `gorm:"primaryKey;size:36" json:"-"`
	ActiveSlot    *string `gorm:"uniqueIndex;size:16" json:"-"`
	MasterGUID    string  `gorm:"size:36" json:"-"`
	Fingerprint   string  `json:"-"`
	MasterCertPEM string  `json:"-"`
	Payload       string  `json:"-"`
	Status        string  `gorm:"size:24;index" json:"-"`
	Deadline      int64   `json:"-"`
	CreatedAt     int64   `gorm:"autoCreateTime:milli" json:"-"`
	UpdatedAt     int64   `gorm:"autoUpdateTime:milli" json:"-"`
}

type ControlCARecipient struct {
	ID             int64  `gorm:"primaryKey;autoIncrement" json:"-"`
	ChangeID       string `gorm:"size:36;uniqueIndex:idx_ca_recipient,priority:1" json:"-"`
	NodeID         int    `gorm:"index;uniqueIndex:idx_ca_recipient,priority:2" json:"-"`
	GUID           string `gorm:"size:36;index" json:"-"`
	OldPeer        string `json:"-"`
	Snapshot       string `json:"-"`
	OriginalEnable bool   `json:"-"`
	CertPEM        string `json:"-"`
	CSRHash        string `json:"-"`
	Status         string `gorm:"size:24;index" json:"-"`
	Attempts       int    `json:"-"`
	NextAttemptAt  int64  `json:"-"`
	LastError      string `json:"-"`
}
