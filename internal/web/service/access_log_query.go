package service

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/mhsanaei/3x-ui/v3/internal/accesslog"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

var ErrInvalidAccessLogQuery = errors.New("invalid_access_log_query")

type AccessLogQuery struct {
	Page      int    `form:"page"`
	PageSize  int    `form:"pageSize"`
	NodeGUID  string `form:"nodeGuid"`
	From      int64  `form:"from"`
	To        int64  `form:"to"`
	User      string `form:"user"`
	UserExact bool   `form:"userExact"`
	Source    string `form:"source"`
	Target    string `form:"target"`
	Inbound   string `form:"inbound"`
	Outbound  string `form:"outbound"`
	Category  string `form:"category"`
}

type AccessLogPage struct {
	Items        []model.AccessLog `json:"items"`
	Total        int64             `json:"total"`
	Page         int               `json:"page"`
	PageSize     int               `json:"pageSize"`
	UserComments map[string]string `json:"userComments"`
}

type AccessLogNodeOption struct {
	GUID  string `json:"guid"`
	Name  string `json:"name"`
	Local bool   `json:"local"`
}

func (q *AccessLogQuery) normalize() error {
	if q.Page == 0 {
		q.Page = 1
	}
	if q.PageSize == 0 {
		q.PageSize = 50
	}
	if q.Page < 1 || q.Page > 1_000_000 || q.PageSize < 1 || q.PageSize > 200 || q.From < 0 || q.To < 0 || q.From > 253402300799999 || q.To > 253402300799999 || q.From > 0 && q.To > 0 && q.From > q.To {
		return ErrInvalidAccessLogQuery
	}
	if q.NodeGUID != "" {
		id, err := uuid.Parse(q.NodeGUID)
		if err != nil || id == uuid.Nil || id.String() != q.NodeGUID {
			return ErrInvalidAccessLogQuery
		}
	}
	if q.Category != "" && q.Category != "direct" && q.Category != "blocked" && q.Category != "proxy" {
		return ErrInvalidAccessLogQuery
	}
	for _, value := range []*string{&q.User, &q.Source, &q.Target, &q.Inbound, &q.Outbound} {
		*value = strings.TrimSpace(*value)
		if !utf8.ValidString(*value) || utf8.RuneCountInString(*value) > 512 {
			return ErrInvalidAccessLogQuery
		}
	}
	return nil
}

// Query reads only this master's archive. Parameters never select a remote
// panel or form SQL identifiers. Text searches treat SQL wildcards literally.
func (s *AccessLogService) Query(ctx context.Context, q AccessLogQuery, now time.Time) (AccessLogPage, error) {
	result := AccessLogPage{Items: []model.AccessLog{}, UserComments: map[string]string{}}
	if err := q.normalize(); err != nil {
		return result, err
	}
	cutoff := now.Add(-accesslog.ArchiveRetention).UnixMilli()
	db := accessDB().WithContext(ctx).Model(&model.AccessLog{}).Where("occurred_at >= ? AND received_at >= ?", cutoff, cutoff)
	if q.NodeGUID != "" {
		db = db.Where("node_guid = ?", q.NodeGUID)
	}
	if q.From > 0 {
		db = db.Where("occurred_at >= ?", q.From)
	}
	if q.To > 0 {
		db = db.Where("occurred_at <= ?", q.To)
	}
	if q.Category != "" {
		db = db.Where("category = ?", q.Category)
	}
	user := q.User
	if q.UserExact && user != "" {
		db = db.Where("email = ?", user)
		user = ""
	}
	for _, filter := range []struct{ column, value string }{
		{"email", user}, {"source", q.Source}, {"target", q.Target}, {"inbound", q.Inbound}, {"outbound", q.Outbound},
	} {
		if filter.value != "" {
			literal := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(strings.ToLower(filter.value))
			db = db.Where("LOWER("+filter.column+") LIKE ? ESCAPE '!'", "%"+literal+"%")
		}
	}
	if err := db.Count(&result.Total).Error; err != nil {
		return result, err
	}
	last := max(int((result.Total+int64(q.PageSize)-1)/int64(q.PageSize)), 1)
	result.Page, result.PageSize = min(q.Page, last), q.PageSize
	if err := db.Order("occurred_at DESC").Order("id DESC").Limit(q.PageSize).Offset((result.Page - 1) * q.PageSize).Find(&result.Items).Error; err != nil {
		return result, err
	}
	if len(result.Items) == 0 {
		return result, nil
	}
	emails := make([]string, 0, len(result.Items))
	for _, row := range result.Items {
		if row.Email != "" {
			emails = append(emails, row.Email)
		}
	}
	// Remarks describe the current user. They do not affect filtering or the
	// archived event, and only the displayed page's public labels are loaded.
	var labels []struct{ Email, Comment string }
	if len(emails) > 0 {
		if err := accessDB().WithContext(ctx).Model(&model.ClientRecord{}).Select("email", "comment").Where("email IN ?", emails).Find(&labels).Error; err != nil {
			return result, err
		}
	}
	for _, label := range labels {
		result.UserComments[label.Email] = label.Comment
	}
	return result, nil
}

// QueryNodes includes historical identities so removing a Node does not make
// its retained logs impossible to select. Only public labels are read.
func (s *AccessLogService) QueryNodes(ctx context.Context, now time.Time) ([]AccessLogNodeOption, error) {
	self, err := (&SettingService{}).ControlIdentity()
	if err != nil {
		return nil, err
	}
	options := []AccessLogNodeOption{{GUID: self.GUID, Local: true}}
	seen := map[string]bool{self.GUID: true}
	var nodes []struct{ Guid, Name string }
	if err := accessDB().WithContext(ctx).Model(&model.Node{}).Select("guid", "name").Where("guid <> ?", "").Order("name ASC").Order("id ASC").Find(&nodes).Error; err != nil {
		return nil, err
	}
	for _, node := range nodes {
		if !seen[node.Guid] {
			seen[node.Guid] = true
			options = append(options, AccessLogNodeOption{GUID: node.Guid, Name: node.Name})
		}
	}
	var archived []string
	cutoff := now.Add(-accesslog.ArchiveRetention).UnixMilli()
	if err := accessDB().WithContext(ctx).Model(&model.AccessLog{}).Where("occurred_at >= ? AND received_at >= ?", cutoff, cutoff).Distinct("node_guid").Order("node_guid ASC").Pluck("node_guid", &archived).Error; err != nil {
		return nil, err
	}
	for _, guid := range archived {
		if !seen[guid] {
			seen[guid] = true
			options = append(options, AccessLogNodeOption{GUID: guid, Name: guid})
		}
	}
	return options, nil
}
