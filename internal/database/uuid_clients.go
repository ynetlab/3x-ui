package database

import (
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"gorm.io/gorm"
)

// migrateUUIDClientCredentials preserves existing UUIDs, fills missing UUIDs
// for the three migrated protocols, and updates their persisted panel snapshots
// before removing the obsolete Hysteria-only client column.
func migrateUUIDClientCredentials() error {
	const seeder = "UUIDClientCredentials"
	var count int64
	if err := db.Model(&model.HistoryOfSeeders{}).Where("seeder_name = ?", seeder).Count(&count).Error; err != nil || count > 0 {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		var records []model.ClientRecord
		if err := tx.Find(&records).Error; err != nil {
			return err
		}
		byEmail := make(map[string]*model.ClientRecord, len(records))
		for i := range records {
			byEmail[strings.ToLower(records[i].Email)] = &records[i]
		}
		var attached []model.ClientRecord
		if err := tx.Model(&model.ClientRecord{}).Select("clients.*").
			Joins("JOIN client_inbounds ON client_inbounds.client_id = clients.id").
			Joins("JOIN inbounds ON inbounds.id = client_inbounds.inbound_id").
			Where("inbounds.protocol IN ?", []model.Protocol{model.Trojan, model.AnyTLS, model.Hysteria}).Distinct().Find(&attached).Error; err != nil {
			return err
		}
		ensureUUID := func(row *model.ClientRecord) error {
			if row.UUID != "" {
				return nil
			}
			row.UUID = uuid.NewString()
			return tx.Model(row).UpdateColumn("uuid", row.UUID).Error
		}
		for _, row := range attached {
			if err := ensureUUID(byEmail[strings.ToLower(row.Email)]); err != nil {
				return err
			}
		}
		var inbounds []model.Inbound
		if err := tx.Find(&inbounds).Error; err != nil {
			return err
		}
		for _, inbound := range inbounds {
			var settings map[string]json.RawMessage
			if json.Unmarshal([]byte(inbound.Settings), &settings) != nil {
				continue
			}
			var clients []map[string]json.RawMessage
			if json.Unmarshal(settings["clients"], &clients) != nil {
				continue
			}
			migrated := inbound.Protocol == model.Trojan || inbound.Protocol == model.AnyTLS || inbound.Protocol == model.Hysteria
			changed := false
			for _, client := range clients {
				if _, ok := client["auth"]; ok {
					delete(client, "auth")
					changed = true
				}
				if !migrated {
					continue
				}
				var email, id string
				_ = json.Unmarshal(client["email"], &email)
				if row := byEmail[strings.ToLower(email)]; row != nil {
					if err := ensureUUID(row); err != nil {
						return err
					}
					id = row.UUID
				} else {
					_ = json.Unmarshal(client["id"], &id)
					if id == "" {
						id = uuid.NewString()
					}
				}
				client["id"], _ = json.Marshal(id)
				delete(client, "password")
				changed = true
			}
			if changed {
				settings["clients"], _ = json.Marshal(clients)
				raw, err := json.Marshal(settings)
				if err != nil {
					return err
				}
				if err := tx.Model(&model.Inbound{}).Where("id = ?", inbound.Id).UpdateColumn("settings", string(raw)).Error; err != nil {
					return err
				}
			}
		}
		if tx.Migrator().HasColumn(&model.ClientRecord{}, "auth") {
			// Both supported databases can drop this unconstrained column directly.
			// SQLite's GORM table recreation misses unquoted legacy column names.
			if err := tx.Exec("ALTER TABLE clients DROP COLUMN auth").Error; err != nil {
				return err
			}
		}
		return tx.Create(&model.HistoryOfSeeders{SeederName: seeder}).Error
	})
}
