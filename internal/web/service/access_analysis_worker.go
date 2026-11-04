package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gorm.io/gorm"

	"github.com/mhsanaei/3x-ui/v3/internal/accesslog"
	"github.com/mhsanaei/3x-ui/v3/internal/accessstats"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

const analysisStateKey = "accessAnalysisState"

type analysisState struct {
	Active       string `json:"active"`
	Building     string `json:"building"`
	Cursor       int64  `json:"cursor"`
	ActiveCursor int64  `json:"activeCursor"`
	TargetID     int64  `json:"targetId"`
}

func readAnalysisState(db *gorm.DB) (analysisState, error) {
	var row model.Setting
	err := db.Where("key = ?", analysisStateKey).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return analysisState{}, nil
	}
	if err != nil {
		return analysisState{}, err
	}
	var state analysisState
	err = json.Unmarshal([]byte(row.Value), &state)
	return state, err
}

func saveAnalysisState(db *gorm.DB, state analysisState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return putPairingSetting(db, analysisStateKey, string(data))
}

type analysisWorker struct {
	classifier      *accessstats.Classifier
	locator         accessstats.Locator
	resourceVersion string
	ruleStamp       string
	backlog         bool
}

// RunAccessAnalysisWorker is independent of archive acknowledgement and slave
// collection. A transaction advances the cursor with all four projections.
func RunAccessAnalysisWorker(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		downloads := runAnalysisDownloads(ctx)
		defer func() { <-downloads }()
		worker := &analysisWorker{}
		defer worker.locator.Close()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		var nextResources, nextPrune, nextWarning time.Time
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			role, err := (&SettingService{}).GetPanelRole()
			if err == nil && role == PanelRoleMaster {
				now := time.Now()
				if now.After(nextResources) {
					file := filepath.Join(assetDir(), "geosite.dat")
					stamp := accessstats.CatalogVersion
					if info, statErr := os.Stat(file); statErr == nil {
						stamp = fmt.Sprintf("%s:%d:%d", stamp, info.Size(), info.ModTime().UnixNano())
					}
					if worker.classifier == nil || worker.ruleStamp != stamp {
						next, loadErr := accessstats.NewClassifier(ctx, assetStore(), "geosite.dat")
						if loadErr == nil {
							worker.classifier = next
							worker.ruleStamp = stamp
							logger.Infof("Access applications: %d services, %d rules, %d ambiguous", next.Report.Applications, next.Report.Rules, next.Report.AmbiguousRules)
						} else {
							if worker.classifier == nil {
								worker.classifier = accessstats.BuiltinClassifier()
							}
							if errors.Is(loadErr, os.ErrNotExist) {
								worker.ruleStamp = stamp
							} else {
								logger.Warningf("Reload access applications: %v; retaining previous rules", loadErr)
							}
						}
					}
					worker.refreshLocation()
					nextResources = now.Add(time.Minute)
				}
				// Catch up in bounded bursts, releasing the archive gate after every
				// 500 rows. Collection/report acknowledgements can run between batches.
				deadline := time.Now().Add(200 * time.Millisecond)
				for range 8 {
					if err = worker.step(ctx, now); err != nil {
						if now.After(nextWarning) {
							logger.Warningf("Access analysis: %v", err)
							nextWarning = now.Add(time.Minute)
						}
						break
					}
					if !worker.backlog || time.Now().After(deadline) {
						break
					}
					runtime.Gosched()
				}
				if now.After(nextPrune) {
					worker.prune(ctx, now)
					nextPrune = now.Add(time.Hour)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}

func (w *analysisWorker) step(ctx context.Context, now time.Time) error {
	if err := lockAccessArchive(ctx); err != nil {
		return err
	}
	defer func() { <-accessArchiveGate }()
	db := accessDB().WithContext(ctx)
	state, err := readAnalysisState(db)
	if err != nil {
		return err
	}
	version := accessstats.Key(w.classifier.Version, w.resourceVersion)
	if state.Building != version {
		state.Building, state.Cursor = version, 0
		// Publish after all pre-existing rows are rebuilt. A busy incoming stream
		// must not postpone the generation switch indefinitely.
		if err = db.Model(&model.AccessLog{}).Select("COALESCE(MAX(id),0)").Scan(&state.TargetID).Error; err != nil {
			return err
		}
	}
	var rows []model.AccessLog
	cutoff := now.Add(-accesslog.ArchiveRetention).UnixMilli()
	if err = db.Where("id > ? AND occurred_at >= ? AND received_at >= ?", state.Cursor, cutoff, cutoff).Order("id").Limit(500).Find(&rows).Error; err != nil {
		return err
	}
	facts := make([]model.AccessLogAnalysis, len(rows))
	for i, row := range rows {
		location := w.locator.Lookup(row.SourceIP)
		facts[i] = model.AccessLogAnalysis{Generation: version, LogID: row.ID, OccurredAt: row.OccurredAt, AppID: w.classifier.Match(row.TargetHost), Domain: accessstats.Domain(row.TargetHost), Country: location.Country, Subdivision: location.Subdivision, Latitude: location.Latitude, Longitude: location.Longitude}
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := projectAccessBatch(tx, rows, facts); err != nil {
			return err
		}
		if len(rows) > 0 {
			state.Cursor = rows[len(rows)-1].ID
		}
		if len(rows) < 500 {
			if err := tx.Model(&model.AccessLog{}).Select("COALESCE(MAX(id),0)").Scan(&state.Cursor).Error; err != nil {
				return err
			}
			state.Active, state.ActiveCursor = version, state.Cursor
		} else if state.Active == version || state.Cursor >= state.TargetID {
			state.Active = version
			state.ActiveCursor = state.Cursor
		}
		return saveAnalysisState(tx, state)
	})
	if err == nil {
		w.backlog = len(rows) == 500
	}
	return err
}

func (w *analysisWorker) prune(ctx context.Context, now time.Time) {
	if err := lockAccessArchive(ctx); err != nil {
		return
	}
	defer func() { <-accessArchiveGate }()
	db := accessDB().WithContext(ctx)
	state, err := readAnalysisState(db)
	if err != nil {
		return
	}
	cutoff := now.Add(-accesslog.ArchiveRetention).UnixMilli()
	for _, target := range []any{&model.AccessLogAnalysis{}, &model.AccessAppStat{}, &model.AccessDomainStat{}, &model.AccessSourceStat{}} {
		column := "minute"
		if _, ok := target.(*model.AccessLogAnalysis); ok {
			column = "occurred_at"
		}
		if err := db.Where(column+" < ? OR generation NOT IN ?", cutoff, []string{state.Active, state.Building}).Delete(target).Error; err != nil {
			logger.Warningf("Prune access analysis: %v", err)
		}
	}
}
