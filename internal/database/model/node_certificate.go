package model

// NodeCertificateJob is durable master-side issuance/deployment state. Payload
// contains a bound, encrypted bundle, never included in HTTP views or SQL logs.
type NodeCertificateJob struct {
	ID            string  `gorm:"primaryKey;size:36" json:"-"`
	NodeID        int     `gorm:"index" json:"-"`
	NodeGUID      string  `gorm:"size:36;index" json:"-"`
	EnrollmentID  string  `gorm:"size:36;index" json:"-"`
	ActiveSlot    *string `gorm:"uniqueIndex;size:36" json:"-"`
	ZoneID        string  `gorm:"size:32" json:"-"`
	Domains       string  `json:"-"`
	RecordIDs     string  `json:"-"`
	PrimaryDomain string  `json:"-"`
	Status        string  `gorm:"size:24;index" json:"-"`
	Payload       string  `json:"-"`
	ACMEState     string  `json:"-"`
	Active        bool    `gorm:"index" json:"-"`
	Fingerprint   string  `gorm:"size:64" json:"-"`
	ExpiresAt     int64   `json:"-"`
	Attempts      int     `json:"-"`
	NextAttemptAt int64   `gorm:"index" json:"-"`
	LastError     string  `gorm:"size:96" json:"-"`
	CreatedAt     int64   `gorm:"autoCreateTime:milli" json:"-"`
	UpdatedAt     int64   `gorm:"autoUpdateTime:milli" json:"-"`
}

// ACMEChallenge records only TXT values owned by this worker. Cleanup after a
// restart never removes another ACME client's or operator's records.
type ACMEChallenge struct {
	ID        string `gorm:"primaryKey;size:36"`
	JobID     string `gorm:"size:36;index"`
	ZoneID    string `gorm:"size:32"`
	RecordID  string `gorm:"size:32"`
	Name      string
	Value     string
	CreatedAt int64 `gorm:"autoCreateTime:milli"`
}
