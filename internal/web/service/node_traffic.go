package service

import (
	"time"

	"gorm.io/gorm"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

// ProtocolTrafficTotals excludes mirrored remote counters and counts a shared
// client once. Inbounds without client counters use their inbound totals.
type ProtocolTrafficTotals struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

func (s *ServerService) getProtocolTraffic(now time.Time) (*ProtocolTrafficTotals, *TrafficQuotaView) {
	s.trafficMu.Lock()
	defer s.trafficMu.Unlock()
	if now.Sub(s.trafficCheckedAt) < 10*time.Second {
		return s.protocolTraffic, s.trafficQuota
	}
	s.trafficCheckedAt = now
	if db := database.GetDB(); db != nil {
		if totals, err := localProtocolTraffic(db); err == nil {
			s.protocolTraffic = totals
		} else {
			s.protocolTraffic = nil
		}
		s.trafficQuota, _ = masterTrafficQuota(s.protocolTraffic, now)
	}
	return s.protocolTraffic, s.trafficQuota
}

func localProtocolTraffic(db *gorm.DB) (*ProtocolTrafficTotals, error) {
	var totals ProtocolTrafficTotals
	err := db.Raw(`WITH remote AS (
		SELECT email, SUM(up) AS up, SUM(down) AS down FROM node_client_traffics GROUP BY email
	), counters AS (
		SELECT CASE WHEN t.up > COALESCE(r.up, 0) THEN t.up - COALESCE(r.up, 0) ELSE 0 END AS up,
		CASE WHEN t.down > COALESCE(r.down, 0) THEN t.down - COALESCE(r.down, 0) ELSE 0 END AS down
		FROM client_traffics t LEFT JOIN remote r ON r.email = t.email
		WHERE EXISTS (SELECT 1 FROM clients c JOIN client_inbounds ci ON ci.client_id = c.id
		JOIN inbounds i ON i.id = ci.inbound_id WHERE c.email = t.email AND i.node_id IS NULL)
		UNION ALL
		SELECT i.up, i.down FROM inbounds i WHERE i.node_id IS NULL
		AND NOT EXISTS (SELECT 1 FROM client_inbounds ci JOIN clients c ON c.id = ci.client_id
		JOIN client_traffics t ON t.email = c.email WHERE ci.inbound_id = i.id)
	) SELECT COALESCE(SUM(up), 0) AS up, COALESCE(SUM(down), 0) AS down FROM counters`).Scan(&totals).Error
	if err != nil {
		return nil, err
	}
	return &totals, nil
}

type NodeTrafficUsage struct {
	Up          int64 `json:"up"`
	Down        int64 `json:"down"`
	PeriodStart int64 `json:"periodStart"`
}

func nodeTrafficUsage(n *model.Node) *NodeTrafficUsage {
	if n.TrafficUpdatedAt == 0 {
		return nil
	}
	return &NodeTrafficUsage{
		Up:          max(0, n.TrafficUp-n.TrafficBaseUp),
		Down:        max(0, n.TrafficDown-n.TrafficBaseDown),
		PeriodStart: n.TrafficPeriodStart,
	}
}

func trafficPeriodStart(now time.Time, day int) time.Time {
	day = min(31, max(1, day))
	boundary := func(year int, month time.Month) time.Time {
		last := time.Date(year, month+1, 0, 0, 0, 0, 0, now.Location()).Day()
		return time.Date(year, month, min(day, last), 0, 0, 0, 0, now.Location())
	}
	start := boundary(now.Year(), now.Month())
	if now.Before(start) {
		start = boundary(now.Year(), now.Month()-1)
	}
	return start
}

func updateNodeTraffic(n *model.Node, totals *ProtocolTrafficTotals, now time.Time) map[string]any {
	period := trafficPeriodStart(now, n.TrafficResetDay).Unix()
	up, down := max(0, totals.Up), max(0, totals.Down)
	baseUp, baseDown := n.TrafficBaseUp, n.TrafficBaseDown
	if n.TrafficPeriodStart > 0 && period > n.TrafficPeriodStart {
		baseUp, baseDown = up, down
	}
	if up < baseUp {
		baseUp = 0
	}
	if down < baseDown {
		baseDown = 0
	}
	return map[string]any{
		"traffic_up": up, "traffic_down": down,
		"traffic_base_up": baseUp, "traffic_base_down": baseDown,
		"traffic_period_start": max(period, n.TrafficPeriodStart),
		"traffic_updated_at":   now.Unix(),
	}
}

func updateTrafficConfig(updates map[string]any, existing *model.Node, limit *int64, day *int) {
	if limit != nil {
		updates["traffic_limit"] = *limit
	}
	if day != nil {
		updates["traffic_reset_day"] = *day
		if *day != max(1, existing.TrafficResetDay) {
			updates["traffic_period_start"] = 0
			updates["traffic_base_up"] = 0
			updates["traffic_base_down"] = 0
		}
	}
}
