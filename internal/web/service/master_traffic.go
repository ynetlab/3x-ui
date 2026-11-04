package service

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

const masterTrafficSetting = "masterTrafficQuota"

var masterTrafficMu sync.Mutex

type TrafficQuotaRequest struct {
	TrafficLimit    int64 `json:"trafficLimit"`
	TrafficResetDay int   `json:"trafficResetDay"`
}

type TrafficQuotaView struct {
	TrafficLimit    int64             `json:"trafficLimit"`
	TrafficResetDay int               `json:"trafficResetDay"`
	TrafficUsage    *NodeTrafficUsage `json:"trafficUsage,omitempty"`
}

type masterTrafficState struct {
	TrafficQuotaRequest
	BaseUp      int64 `json:"baseUp"`
	BaseDown    int64 `json:"baseDown"`
	PeriodStart int64 `json:"periodStart"`
}

func readMasterTraffic() (*masterTrafficState, error) {
	state := &masterTrafficState{TrafficQuotaRequest: TrafficQuotaRequest{TrafficResetDay: 1}}
	row, err := (&SettingService{}).getSetting(masterTrafficSetting)
	if database.IsNotFound(err) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(row.Value), state); err != nil {
		return nil, err
	}
	return state, nil
}

func saveMasterTraffic(state *masterTrafficState) error {
	value, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return (&SettingService{}).saveSetting(masterTrafficSetting, string(value))
}

func masterTrafficQuota(totals *ProtocolTrafficTotals, now time.Time) (*TrafficQuotaView, error) {
	masterTrafficMu.Lock()
	defer masterTrafficMu.Unlock()
	settings := &SettingService{}
	role, err := settings.GetPanelRole()
	if err != nil {
		return nil, err
	}
	if role != PanelRoleMaster {
		return nil, nil
	}
	state, err := readMasterTraffic()
	if err != nil {
		return nil, err
	}
	view := &TrafficQuotaView{TrafficLimit: state.TrafficLimit, TrafficResetDay: state.TrafficResetDay}
	if totals == nil {
		return view, nil
	}
	location, err := settings.GetTimeLocation()
	if err != nil {
		return nil, err
	}
	n := &model.Node{TrafficResetDay: state.TrafficResetDay, TrafficBaseUp: state.BaseUp, TrafficBaseDown: state.BaseDown, TrafficPeriodStart: state.PeriodStart}
	updates := updateNodeTraffic(n, totals, now.In(location))
	n.TrafficUp, n.TrafficDown, n.TrafficUpdatedAt = totals.Up, totals.Down, now.Unix()
	n.TrafficBaseUp = updates["traffic_base_up"].(int64)
	n.TrafficBaseDown = updates["traffic_base_down"].(int64)
	n.TrafficPeriodStart = updates["traffic_period_start"].(int64)
	view.TrafficUsage = nodeTrafficUsage(n)
	if state.TrafficLimit > 0 && (state.BaseUp != n.TrafficBaseUp || state.BaseDown != n.TrafficBaseDown || state.PeriodStart != n.TrafficPeriodStart) {
		state.BaseUp, state.BaseDown, state.PeriodStart = n.TrafficBaseUp, n.TrafficBaseDown, n.TrafficPeriodStart
		if err := saveMasterTraffic(state); err != nil {
			return nil, err
		}
	}
	return view, nil
}

func (s *ServerService) SetMasterTrafficQuota(request TrafficQuotaRequest) error {
	if request.TrafficLimit < 0 || request.TrafficLimit > 9007199254740991 || request.TrafficResetDay < 1 || request.TrafficResetDay > 31 {
		return fmt.Errorf("invalid traffic quota")
	}
	s.trafficMu.Lock()
	defer s.trafficMu.Unlock()
	masterTrafficMu.Lock()
	defer masterTrafficMu.Unlock()
	role, err := (&SettingService{}).GetPanelRole()
	if err != nil {
		return err
	}
	if role != PanelRoleMaster {
		return fmt.Errorf("master required")
	}
	state, err := readMasterTraffic()
	if err != nil {
		return err
	}
	if request.TrafficResetDay != state.TrafficResetDay {
		state.BaseUp, state.BaseDown, state.PeriodStart = 0, 0, 0
	}
	state.TrafficQuotaRequest = request
	if err := saveMasterTraffic(state); err != nil {
		return err
	}
	s.trafficCheckedAt = time.Time{}
	return nil
}
