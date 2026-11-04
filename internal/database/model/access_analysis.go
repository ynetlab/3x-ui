package model

// AccessLogAnalysis and the three minute rollups are disposable projections.
// Generations allow a changed catalog/database to rebuild without mixed results.
type AccessLogAnalysis struct {
	Generation  string `gorm:"primaryKey;size:64"`
	LogID       int64  `gorm:"primaryKey;autoIncrement:false"`
	OccurredAt  int64  `gorm:"index"`
	AppID       string `gorm:"size:64"`
	Domain      string
	Country     string `gorm:"size:2"`
	Subdivision string `gorm:"size:128"`
	Latitude    float64
	Longitude   float64
}

func (AccessLogAnalysis) TableName() string { return "access_log_analysis" }

type AccessAppStat struct {
	Key        string `gorm:"primaryKey;size:64"`
	Generation string `gorm:"size:64;index:idx_app_generation_time,priority:1"`
	Minute     int64  `gorm:"index:idx_app_generation_time,priority:2"`
	NodeGUID   string `gorm:"size:36"`
	Email      string
	AppID      string `gorm:"size:64"`
	Category   string `gorm:"size:16"`
	Count      int64
}

type AccessDomainStat struct {
	Key        string `gorm:"primaryKey;size:64"`
	Generation string `gorm:"size:64;index:idx_domain_generation_time,priority:1"`
	Minute     int64  `gorm:"index:idx_domain_generation_time,priority:2"`
	NodeGUID   string `gorm:"size:36"`
	Email      string
	AppID      string `gorm:"size:64"`
	Domain     string
	Category   string `gorm:"size:16"`
	Count      int64
}

type AccessSourceStat struct {
	Key         string `gorm:"primaryKey;size:64"`
	Generation  string `gorm:"size:64;index:idx_source_generation_time,priority:1"`
	Minute      int64  `gorm:"index:idx_source_generation_time,priority:2"`
	NodeGUID    string `gorm:"size:36"`
	Email       string
	SourceIP    string `gorm:"size:45"`
	Country     string `gorm:"size:2"`
	Subdivision string `gorm:"size:128"`
	Latitude    float64
	Longitude   float64
	Category    string `gorm:"size:16"`
	Count       int64
	LastSeen    int64
}
