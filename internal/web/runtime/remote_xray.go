package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type NodeXrayResponse struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

// NodeXrayEndpoint limits online editing to configuration, its references and
// the diagnostics used by the routing/outbound editors. It is not a general proxy.
func NodeXrayEndpoint(method, path string) bool {
	switch method {
	case http.MethodGet:
		switch path {
		case "/xray/getOutboundsTraffic", "/xray/geodata/files", "/xray/geodata/categories", "/xray/geodata/entries",
			"/xray/outbound-subs", "/xray/getDefaultJsonConfig", "/xray/getXrayResult", "/setting/getDefaultJsonConfig",
			"/inbounds/options", "/clients/list":
			return true
		}
	case http.MethodPost:
		switch path {
		case "/xray/", "/xray/update", "/xray/testOutbound", "/xray/testOutbounds",
			"/xray/resetOutboundsTraffic", "/xray/routeTest", "/xray/geodata/validate",
			"/xray/outbound-subs", "/xray/outbound-subs/parse", "/xray/balancerStatus", "/xray/balancerOverride",
			"/setting/all", "/setting/update", "/setting/factoryDefaults", "/setting/restartPanel":
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
