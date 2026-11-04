package service

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/mhsanaei/3x-ui/v3/internal/accesslog"
	"github.com/mhsanaei/3x-ui/v3/internal/accessstats"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

type AccessAnalysisQuery struct {
	AccessLogQuery
	UserSet bool   `form:"userSet"`
	Kind    string `form:"kind"`
}

type AccessAnalysisItem struct {
	Name        string  `json:"name"`
	Count       int64   `json:"count"`
	LastSeen    int64   `json:"lastSeen"`
	Country     string  `json:"country"`
	Subdivision string  `json:"subdivision"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

type AccessAnalysisPage struct {
	Items        []AccessAnalysisItem      `json:"items"`
	Total        int64                     `json:"total"`
	Page         int                       `json:"page"`
	PageSize     int                       `json:"pageSize"`
	UserComments map[string]string         `json:"userComments"`
	Catalog      []accessstats.Application `json:"catalog"`
}

type AccessAnalysisStatus struct {
	Ready         bool   `json:"ready"`
	Rebuilding    bool   `json:"rebuilding"`
	ProcessedID   int64  `json:"processedId"`
	LatestID      int64  `json:"latestId"`
	LocationReady bool   `json:"locationReady"`
	Generation    string `json:"generation"`
}

type AccessAnalysisOverview struct {
	Status       AccessAnalysisStatus      `json:"status"`
	Total        int64                     `json:"total"`
	Apps         []AccessAnalysisItem      `json:"apps"`
	Domains      []AccessAnalysisItem      `json:"domains"`
	Sources      []AccessAnalysisItem      `json:"sources"`
	Regions      []AccessAnalysisItem      `json:"regions"`
	Users        []AccessAnalysisItem      `json:"users"`
	Blocked      []model.AccessLog         `json:"blocked"`
	UserComments map[string]string         `json:"userComments"`
	Catalog      []accessstats.Application `json:"catalog"`
}

type AccessAnalysisService struct{}

func analysisStatus(db *gorm.DB, state analysisState) (AccessAnalysisStatus, error) {
	status := AccessAnalysisStatus{Ready: state.Active != "", Rebuilding: state.Building != state.Active, ProcessedID: state.ActiveCursor, Generation: state.Active}
	err := db.Model(&model.AccessLog{}).Select("COALESCE(MAX(id),0)").Scan(&status.LatestID).Error
	_, statErr := os.Stat(analysisCityPath())
	status.LocationReady = statErr == nil
	return status, err
}

func analysisLabels(db *gorm.DB, emails []string) (map[string]string, error) {
	labels := map[string]string{}
	if len(emails) == 0 {
		return labels, nil
	}
	var rows []struct{ Email, Comment string }
	if err := db.Model(&model.ClientRecord{}).Select("email, comment").Where("email IN ?", emails).Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, row := range rows {
		labels[row.Email] = row.Comment
	}
	return labels, nil
}

// analysisSeries combines complete UTC-minute buckets with exact raw edges.
// It never rounds a user's range outwards or counts the same edge twice.
func analysisSeries(db *gorm.DB, q AccessAnalysisQuery, generation, kind string, now time.Time) *gorm.DB {
	from := max(q.From, now.Add(-accesslog.ArchiveRetention).UnixMilli())
	to := q.To
	if to == 0 {
		to = now.UnixMilli()
	}
	fullStart := (from + 59999) / 60000 * 60000
	fullEnd := (to + 1) / 60000 * 60000
	table, name, rawName := "access_app_stats", "app_id", "a.app_id"
	if kind == "users" {
		name, rawName = "email", "l.email"
	}
	if kind == "domains" {
		table, name, rawName = "access_domain_stats", "domain", "a.domain"
	}
	if kind == "sources" || kind == "regions" {
		table, name, rawName = "access_source_stats", "source_ip", "l.source_ip"
	}
	columns := name + " AS name, '' AS country, '' AS subdivision, 0.0 AS latitude, 0.0 AS longitude, count, minute AS last_seen"
	rawColumns := rawName + " AS name, '' AS country, '' AS subdivision, 0.0 AS latitude, 0.0 AS longitude, 1 AS count, l.occurred_at AS last_seen"
	if table == "access_source_stats" {
		columns = name + " AS name, country, subdivision, latitude, longitude, count, last_seen"
		rawColumns = rawName + " AS name, a.country, a.subdivision, a.latitude, a.longitude, 1 AS count, l.occurred_at AS last_seen"
	}
	rollup := db.Table(table).Select(columns).Where("generation = ? AND minute >= ? AND minute < ?", generation, fullStart, fullEnd)
	raw := db.Table("access_logs AS l").Select(rawColumns).Joins("JOIN access_log_analysis AS a ON a.log_id = l.id AND a.generation = ?", generation).Where("l.occurred_at >= ? AND l.occurred_at <= ? AND l.received_at >= ?", from, to, now.Add(-accesslog.ArchiveRetention).UnixMilli())
	if kind == "domains" {
		raw = raw.Where("a.domain <> ?", "")
	}
	if fullEnd > fullStart {
		raw = raw.Where("(l.occurred_at < ? OR l.occurred_at >= ?)", fullStart, fullEnd)
	}
	for _, filter := range []struct {
		column, value string
		set           bool
	}{
		{"node_guid", q.NodeGUID, q.NodeGUID != ""}, {"email", q.User, q.User != "" || q.UserSet}, {"category", q.Category, q.Category != ""},
	} {
		if filter.set {
			rollup = rollup.Where(filter.column+" = ?", filter.value)
			raw = raw.Where("l."+filter.column+" = ?", filter.value)
		}
	}
	return db.Table("(? UNION ALL ?) AS series", rollup, raw)
}

func analysisGroup(series *gorm.DB, kind string) *gorm.DB {
	columns := "name, SUM(count) AS count, MAX(last_seen) AS last_seen, '' AS country, '' AS subdivision, 0.0 AS latitude, 0.0 AS longitude"
	group := "name"
	if kind == "sources" {
		columns = "name, country, subdivision, AVG(latitude) AS latitude, AVG(longitude) AS longitude, SUM(count) AS count, MAX(last_seen) AS last_seen"
		group = "name, country, subdivision"
	}
	if kind == "regions" {
		columns = "'' AS name, country, subdivision, AVG(latitude) AS latitude, AVG(longitude) AS longitude, SUM(count) AS count, MAX(last_seen) AS last_seen"
		group = "country, subdivision"
	}
	return series.Select(columns).Group(group)
}

func normalizeAnalysisQuery(q *AccessAnalysisQuery) error {
	if err := q.normalize(); err != nil {
		return err
	}
	if q.Kind != "" && q.Kind != "apps" && q.Kind != "users" && q.Kind != "domains" && q.Kind != "sources" {
		return ErrInvalidAccessLogQuery
	}
	// These are deliberately not silently accepted as unsupported filters.
	if strings.Join([]string{q.Source, q.Target, q.Inbound, q.Outbound}, "") != "" {
		return ErrInvalidAccessLogQuery
	}
	return nil
}

func (s *AccessAnalysisService) Page(ctx context.Context, q AccessAnalysisQuery, now time.Time) (AccessAnalysisPage, error) {
	result := AccessAnalysisPage{Items: []AccessAnalysisItem{}, UserComments: map[string]string{}, Catalog: []accessstats.Application{}}
	if err := normalizeAnalysisQuery(&q); err != nil {
		return result, err
	}
	if q.Kind == "" {
		q.Kind = "users"
	}
	db := accessDB().WithContext(ctx)
	err := db.Transaction(func(db *gorm.DB) error {
		state, err := readAnalysisState(db)
		if err != nil {
			return err
		}
		grouped := analysisGroup(analysisSeries(db, q, state.Active, q.Kind, now), q.Kind)
		if err = db.Table("(?) AS grouped", grouped).Count(&result.Total).Error; err != nil {
			return err
		}
		result.PageSize = q.PageSize
		result.Page = min(q.Page, max(1, int((result.Total+int64(q.PageSize)-1)/int64(q.PageSize))))
		if err = grouped.Order("count DESC").Order("name ASC").Limit(q.PageSize).Offset((result.Page - 1) * q.PageSize).Scan(&result.Items).Error; err != nil {
			return err
		}
		if q.Kind == "apps" {
			for _, row := range result.Items {
				if row.Name != "unknown" {
					result.Catalog = append(result.Catalog, accessstats.ApplicationMetadata(row.Name))
				}
			}
		}
		if q.Kind == "users" {
			emails := make([]string, 0, len(result.Items))
			for _, row := range result.Items {
				emails = append(emails, row.Name)
			}
			result.UserComments, err = analysisLabels(db, emails)
		}
		return err
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	return result, err
}

func (s *AccessAnalysisService) Overview(ctx context.Context, q AccessAnalysisQuery, now time.Time) (AccessAnalysisOverview, error) {
	result := AccessAnalysisOverview{Apps: []AccessAnalysisItem{}, Domains: []AccessAnalysisItem{}, Sources: []AccessAnalysisItem{}, Regions: []AccessAnalysisItem{}, Users: []AccessAnalysisItem{}, Blocked: []model.AccessLog{}, UserComments: map[string]string{}, Catalog: []accessstats.Application{}}
	if err := normalizeAnalysisQuery(&q); err != nil {
		return result, err
	}
	db := accessDB().WithContext(ctx)
	// One snapshot prevents a generation switch/prune between overview sections.
	err := db.Transaction(func(tx *gorm.DB) error {
		state, err := readAnalysisState(tx)
		if err != nil {
			return err
		}
		result.Status, err = analysisStatus(tx, state)
		if err != nil {
			return err
		}
		for _, section := range []struct {
			kind  string
			rows  *[]AccessAnalysisItem
			limit int
		}{
			{"apps", &result.Apps, 24}, {"domains", &result.Domains, 10}, {"sources", &result.Sources, 10}, {"regions", &result.Regions, 10000}, {"users", &result.Users, 10},
		} {
			order := "count DESC"
			if section.kind == "sources" {
				order = "last_seen DESC"
			}
			query := analysisGroup(analysisSeries(tx, q, state.Active, section.kind, now), section.kind)
			if err = query.Order(order).Order("name ASC").Limit(section.limit).Scan(section.rows).Error; err != nil {
				return err
			}
		}
		for _, app := range result.Apps {
			if app.Name != "unknown" {
				result.Catalog = append(result.Catalog, accessstats.ApplicationMetadata(app.Name))
			}
		}
		if err := analysisSeries(tx, q, state.Active, "apps", now).Select("COALESCE(SUM(count),0)").Scan(&result.Total).Error; err != nil {
			return err
		}
		blocked := tx.Where("id <= ?", state.ActiveCursor).Where("category = ? AND occurred_at >= ? AND received_at >= ?", "blocked", max(q.From, now.Add(-accesslog.ArchiveRetention).UnixMilli()), now.Add(-accesslog.ArchiveRetention).UnixMilli())
		if q.To > 0 {
			blocked = blocked.Where("occurred_at <= ?", q.To)
		} else {
			blocked = blocked.Where("occurred_at <= ?", now.UnixMilli())
		}
		if q.NodeGUID != "" {
			blocked = blocked.Where("node_guid = ?", q.NodeGUID)
		}
		if q.User != "" || q.UserSet {
			blocked = blocked.Where("email = ?", q.User)
		}
		if q.Category != "" && q.Category != "blocked" {
			blocked = blocked.Where("1 = 0")
		}
		if err = blocked.Order("occurred_at DESC").Order("id DESC").Limit(10).Find(&result.Blocked).Error; err != nil {
			return err
		}
		emails := make([]string, 0, len(result.Users))
		for _, row := range result.Users {
			emails = append(emails, row.Name)
		}
		result.UserComments, err = analysisLabels(tx, emails)
		return err
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, fmt.Errorf("access analysis: %w", err)
	}
	return result, nil
}
