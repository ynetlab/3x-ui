package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/nodeip"
)

var nodeIPWake = make(chan struct{}, 1)

type NodeIPService struct{}

func (s *NodeIPService) Get(ctx context.Context, nodeID int) (model.NodePublicIP, error) {
	role, err := (&SettingService{}).GetPanelRole()
	if err != nil {
		return model.NodePublicIP{}, err
	}
	if role != PanelRoleMaster {
		return model.NodePublicIP{}, dnsError(403, "cloudflare_requires_master")
	}
	var node model.Node
	if nodeID < 1 {
		return model.NodePublicIP{}, dnsError(400, "invalid_cloudflare_node")
	}
	if err := dnsDB().WithContext(ctx).Select("id", "guid").First(&node, nodeID).Error; err != nil {
		if database.IsNotFound(err) {
			return model.NodePublicIP{}, dnsError(404, "cloudflare_node_not_found")
		}
		return model.NodePublicIP{}, err
	}
	var value model.NodePublicIP
	err = dnsDB().WithContext(ctx).Where("node_id = ? AND node_guid = ?", node.Id, node.Guid).First(&value).Error
	if database.IsNotFound(err) {
		return model.NodePublicIP{NodeID: node.Id, NodeGUID: node.Guid}, nil
	}
	return value, err
}

// Store is called only after the control router authenticates a bound slave.
// Missing address families update availability but retain last known addresses.
func (s *NodeIPService) Store(ctx context.Context, guid string, report nodeip.Report, now time.Time) error {
	if report.ObservedAt <= 0 || report.ObservedAt > now.Add(5*time.Minute).UnixMilli() {
		return dnsError(400, "invalid_node_ip_report")
	}
	for _, pair := range []struct {
		value *string
		v4    bool
	}{{&report.IPv4, true}, {&report.IPv6, false}} {
		if *pair.value != "" {
			ip, err := nodeip.PublicIP(*pair.value, pair.v4)
			if err != nil {
				return dnsError(400, "invalid_node_ip_report")
			}
			*pair.value = ip
		}
	}
	err := dnsDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var nodes []model.Node
		if err := tx.Select("id", "guid").Where("guid = ? AND control_connection = ?", guid, true).Limit(2).Find(&nodes).Error; err != nil {
			return err
		}
		if len(nodes) != 1 {
			return dnsError(403, "node_ip_node_not_registered")
		}
		row := model.NodePublicIP{NodeID: nodes[0].Id, NodeGUID: guid, IPv4: report.IPv4, IPv6: report.IPv6, IPv4Available: report.IPv4 != "", IPv6Available: report.IPv6 != "", ObservedAt: report.ObservedAt, ReceivedAt: now.UnixMilli()}
		updates := map[string]any{"node_guid": guid, "ipv4_available": row.IPv4Available, "ipv6_available": row.IPv6Available, "observed_at": row.ObservedAt, "received_at": row.ReceivedAt}
		for _, column := range []string{"ipv4", "ipv6"} {
			updates[column] = gorm.Expr("CASE WHEN excluded." + column + " = '' AND node_public_ips.node_guid = excluded.node_guid THEN node_public_ips." + column + " ELSE excluded." + column + " END")
		}
		return tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "node_id"}}, DoUpdates: clause.Assignments(updates), Where: clause.Where{Exprs: []clause.Expression{clause.Expr{SQL: "node_public_ips.node_guid <> excluded.node_guid OR node_public_ips.observed_at < excluded.observed_at"}}}}).Create(&row).Error
	})
	if err == nil {
		select {
		case nodeIPWake <- struct{}{}:
		default:
		}
	}
	return err
}

func (s *NodeIPService) RegisterControlRoutes(router *cluster.Router) {
	router.HandleSlave("POST "+nodeip.ReportPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := cluster.AuthenticatedPeer(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var report nodeip.Report
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&report) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid_node_ip_report", http.StatusBadRequest)
			return
		}
		if err := s.Store(r.Context(), peer.GUID, report, time.Now()); err != nil {
			var local *CloudflareDNSError
			if errors.As(err, &local) {
				http.Error(w, local.Code, local.Status)
			} else {
				http.Error(w, "node_ip_storage_error", http.StatusServiceUnavailable)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"accepted": true, "observedAt": report.ObservedAt})
	}))
}
