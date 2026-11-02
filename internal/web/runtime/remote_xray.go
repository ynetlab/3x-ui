package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

type NodeXrayResponse struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

// NodeXrayEndpoint limits online management to configuration, its references,
// diagnostics and explicit panel/core update controls. It is not a general proxy.
func NodeXrayEndpoint(method, path string) bool {
	switch method {
	case http.MethodGet:
		switch path {
		// Configuration and editor references.
		case "/xray/getOutboundsTraffic", "/xray/geodata/files", "/xray/geodata/categories", "/xray/geodata/entries",
			"/xray/outbound-subs", "/xray/getDefaultJsonConfig", "/xray/getXrayResult", "/setting/getDefaultJsonConfig",
			"/inbounds/options", "/clients/list",
			// System status and diagnostics.
			"/server/status", "/server/getConfigJson", "/server/xrayMetricsState", "/server/xrayObservatory",
			// Panel and core update information.
			"/server/getPanelUpdateInfo", "/server/getUpdateStatus", "/server/getXrayVersion":
			return true
		}
	case http.MethodPost:
		switch path {
		// Xray configuration, subscriptions and diagnostics.
		case "/xray/", "/xray/update", "/xray/testOutbound", "/xray/testOutbounds",
			"/xray/resetOutboundsTraffic", "/xray/routeTest", "/xray/geodata/validate",
			"/xray/outbound-subs", "/xray/outbound-subs/parse", "/xray/balancerStatus", "/xray/balancerOverride",
			// Panel settings and restart.
			"/setting/all", "/setting/update", "/setting/factoryDefaults", "/setting/restartPanel",
			// Core lifecycle controls.
			"/server/stopXrayService", "/server/restartXrayService",
			// Panel and geofile updates.
			"/server/updatePanel", "/server/setUpdateChannel", "/server/updateGeofile":
			return true
		}
		for provider, actions := range map[string][]string{
			"warp": {"data", "del", "config", "reg", "regMasque", "changeIp", "license", "interval"},
			"nord": {"countries", "servers", "reg", "setKey", "data", "del"},
			"pia":  {"countries", "servers", "reg", "data", "del", "addKey"},
		} {
			for _, action := range actions {
				if path == "/xray/"+provider+"/"+action {
					return true
				}
			}
		}
	}
	parts := strings.Split(strings.TrimPrefix(path, "/server/"), "/")
	if strings.HasPrefix(path, "/server/") {
		if method == http.MethodPost && len(parts) == 2 {
			switch parts[0] {
			case "installXray":
				// The existing installer also requires a tag from the release list.
				return safeNodeUpdateSegment(parts[1])
			case "updateGeofile":
				return safeNodeUpdateSegment(parts[1]) && strings.HasSuffix(parts[1], ".dat")
			}
		}
		if method == http.MethodPost && len(parts) == 2 && (parts[0] == "logs" || parts[0] == "xraylogs") {
			count, err := strconv.Atoi(parts[1])
			return err == nil && count > 0 && count <= 10000
		}
		if method == http.MethodGet && len(parts) == 3 {
			bucket, err := strconv.Atoi(parts[2])
			if err != nil || bucket <= 0 {
				return false
			}
			switch parts[0] {
			case "history":
				return slices.Contains([]string{"cpu", "mem", "swap", "netUp", "netDown", "pktUp", "pktDown", "diskRead", "diskWrite", "diskUsage", "tcpCount", "udpCount", "online", "load1", "load5", "load15"}, parts[1])
			case "xrayMetricsHistory":
				return slices.Contains([]string{"xrAlloc", "xrSys", "xrHeapObjects", "xrNumGC", "xrPauseNs"}, parts[1])
			case "xrayObservatoryHistory":
				return parts[1] != "" && parts[1] != "." && parts[1] != ".."
			}
		}
	}
	if suffix, ok := strings.CutPrefix(path, "/xray/outbound-subs/"); ok {
		parts := strings.Split(suffix, "/")
		id, err := strconv.Atoi(parts[0])
		if err != nil || id <= 0 {
			return false
		}
		if len(parts) == 1 {
			return method == http.MethodPost || method == http.MethodDelete
		}
		if len(parts) == 2 && method == http.MethodPost {
			return parts[1] == "refresh" || parts[1] == "move" || parts[1] == "del"
		}
	}
	return false
}

func safeNodeUpdateSegment(value string) bool {
	if value == "" || value == "." || strings.Contains(value, "..") {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == '-') {
			return false
		}
	}
	return true
}

// XrayRequest uses the node's existing panel API; the master keeps no desired
// configuration and never schedules a retry for these online operations.
func (r *Remote) XrayRequest(ctx context.Context, method, path string, query, form url.Values) (*NodeXrayResponse, error) {
	if !NodeXrayEndpoint(method, path) {
		return nil, errors.New("endpoint is not available for node Xray editing")
	}
	params := make(url.Values, len(query))
	for key, values := range query {
		if key != "nodeId" {
			params[key] = append([]string(nil), values...)
		}
	}
	target := "panel/api/" + strings.TrimPrefix(path, "/")
	if encoded := params.Encode(); encoded != "" {
		target += "?" + encoded
	}
	var body any
	if method == http.MethodPost {
		body = form
	}
	// Core reconciliation and batches of outbound probes can outlast a normal
	// node poll. Keep their deadline separate from traffic/heartbeat requests.
	env, err := r.doWithTimeout(ctx, method, target, body, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	return &NodeXrayResponse{Success: env.Success, Msg: env.Msg, Obj: env.Obj}, nil
}
