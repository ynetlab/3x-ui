package service

import (
	"errors"
	"net/netip"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/mhsanaei/3x-ui/v3/internal/accessstats"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func projectAccessBatch(tx *gorm.DB, rows []model.AccessLog, facts []model.AccessLogAnalysis) error {
	if len(rows) == 0 {
		return nil
	}
	ids := make([]int64, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	var existing []int64
	if err := tx.Model(&model.AccessLogAnalysis{}).Where("generation = ? AND log_id IN ?", facts[0].Generation, ids).Pluck("log_id", &existing).Error; err != nil {
		return err
	}
	seen := make(map[int64]bool, len(existing))
	for _, id := range existing {
		seen[id] = true
	}
	newFacts := make([]model.AccessLogAnalysis, 0, len(rows))
	apps := map[string]model.AccessAppStat{}
	domains := map[string]model.AccessDomainStat{}
	sources := map[string]model.AccessSourceStat{}
	for i, row := range rows {
		if seen[row.ID] {
			continue
		}
		fact := facts[i]
		newFacts = append(newFacts, fact)
		minute := row.OccurredAt / 60000 * 60000
		appKey := accessstats.Key(fact.Generation, minute, row.NodeGUID, row.Email, fact.AppID, row.Category)
		app := apps[appKey]
		if app.Count == 0 {
			app = model.AccessAppStat{Key: appKey, Generation: fact.Generation, Minute: minute, NodeGUID: row.NodeGUID, Email: row.Email, AppID: fact.AppID, Category: row.Category}
		}
		app.Count++
		apps[appKey] = app
		host := accessstats.Host(row.TargetHost)
		// IP targets remain in totals and applications but are not domain names.
		if _, err := netip.ParseAddr(host); err != nil && host != "" {
			key := accessstats.Key(fact.Generation, minute, row.NodeGUID, row.Email, fact.AppID, host, row.Category)
			domain := domains[key]
			if domain.Count == 0 {
				domain = model.AccessDomainStat{Key: key, Generation: fact.Generation, Minute: minute, NodeGUID: row.NodeGUID, Email: row.Email, AppID: fact.AppID, Domain: host, Category: row.Category}
			}
			domain.Count++
			domains[key] = domain
		}
		sourceKey := accessstats.Key(fact.Generation, minute, row.NodeGUID, row.Email, row.SourceIP, fact.Country, fact.Subdivision, row.Category)
		source := sources[sourceKey]
		if source.Count == 0 {
			source = model.AccessSourceStat{Key: sourceKey, Generation: fact.Generation, Minute: minute, NodeGUID: row.NodeGUID, Email: row.Email, SourceIP: row.SourceIP, Country: fact.Country, Subdivision: fact.Subdivision, Latitude: fact.Latitude, Longitude: fact.Longitude, Category: row.Category}
		}
		source.Count++
		source.LastSeen = max(source.LastSeen, row.OccurredAt)
		sources[sourceKey] = source
	}
	if len(newFacts) == 0 {
		return nil
	}
	insert := tx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(&newFacts, 50)
	if insert.Error != nil {
		return insert.Error
	}
	if insert.RowsAffected != int64(len(newFacts)) {
		return errors.New("access analysis concurrent projection; retry")
	}
	appRows := make([]model.AccessAppStat, 0, len(apps))
	for _, row := range apps {
		appRows = append(appRows, row)
	}
	domainRows := make([]model.AccessDomainStat, 0, len(domains))
	for _, row := range domains {
		domainRows = append(domainRows, row)
	}
	sourceRows := make([]model.AccessSourceStat, 0, len(sources))
	for _, row := range sources {
		sourceRows = append(sourceRows, row)
	}
	for _, group := range []struct {
		rows  any
		count int
		table string
	}{
		{&appRows, len(appRows), "access_app_stats"}, {&domainRows, len(domainRows), "access_domain_stats"}, {&sourceRows, len(sourceRows), "access_source_stats"},
	} {
		if group.count == 0 {
			continue
		}
		updates := map[string]any{"count": gorm.Expr(group.table + ".count + excluded.count")}
		if group.table == "access_source_stats" {
			updates["last_seen"] = gorm.Expr("CASE WHEN access_source_stats.last_seen > excluded.last_seen THEN access_source_stats.last_seen ELSE excluded.last_seen END")
		}
		if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "key"}}, DoUpdates: clause.Assignments(updates)}).CreateInBatches(group.rows, 50).Error; err != nil {
			return err
		}
	}
	return nil
}
