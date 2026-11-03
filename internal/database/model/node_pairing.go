package model

// NodeEnrollment is the master-side, durable claim of a one-time token.
// Only the explicit service view is returned by HTTP handlers.
type NodeEnrollment struct {
	ID                  string  `gorm:"primaryKey;size:36" json:"-"`
	Name                string  `json:"-"`
	ActiveName          *string `gorm:"uniqueIndex;size:256" json:"-"`
	ActiveGUID          *string `gorm:"uniqueIndex;size:36" json:"-"`
	TokenHash           string  `gorm:"uniqueIndex;size:64" json:"-"`
	Status              string  `gorm:"index;size:24" json:"-"`
	ExpiresAt           int64   `json:"-"`
	ResumeUntil         int64   `json:"-"`
	SlaveGUID           string  `gorm:"index;size:36" json:"-"`
	CSRHash             string  `json:"-"`
	CertPEM             string  `json:"-"`
	Address             string  `json:"-"`
	Port                int     `json:"-"`
	BasePath            string  `json:"-"`
	AdminHash           string  `json:"-"`
	AllowPrivateAddress bool    `json:"-"`
	NodeID              int     `json:"-"`
	ExistingNodeID      int     `json:"-"`
	ActiveNodeID        *int    `gorm:"uniqueIndex" json:"-"`
	ExpectedGUID        string  `json:"-"`
	MigrationSnapshot   string  `json:"-"`
	OriginalEnable      bool    `json:"-"`
	Recovery            bool    `json:"-"`
	RecoveryFingerprint string  `json:"-"`
	LastError           string  `json:"-"`
	Domains             string  `json:"-"`
	PrimaryDomain       string  `json:"-"`
	ZoneID              string  `json:"-"`
	Registration        string  `json:"-"`
	CreatedAt           int64   `gorm:"autoCreateTime:milli" json:"-"`
	UpdatedAt           int64   `gorm:"autoUpdateTime:milli" json:"-"`
}

// NodeJoinJob keeps locally generated keys and secrets in Payload, protected
// using the configured node-token codec and a job-specific binding.
type NodeJoinJob struct {
	Recovery      bool    `json:"-"`
	ID            string  `gorm:"primaryKey;size:36" json:"-"`
	ActiveSlot    *string `gorm:"uniqueIndex;size:16" json:"-"`
	EnrollmentID  string  `gorm:"index;size:36" json:"-"`
	MasterGUID    string  `gorm:"size:36" json:"-"`
	RequestHash   string  `json:"-"`
	Status        string  `gorm:"index;size:24" json:"-"`
	Payload       string  `json:"-"`
	Deadline      int64   `json:"-"`
	NextAttemptAt int64   `gorm:"index" json:"-"`
	Attempts      int     `json:"-"`
	Failures      int     `json:"-"`
	AdminTokenID  int     `json:"-"`
	NodeID        int     `json:"-"`
	LastError     string  `json:"-"`
	CreatedAt     int64   `gorm:"autoCreateTime:milli" json:"-"`
	UpdatedAt     int64   `gorm:"autoUpdateTime:milli" json:"-"`
}
