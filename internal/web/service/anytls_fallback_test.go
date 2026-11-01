package service

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/anytls"
)

func TestAnyTLSFallbackGeneratedConfigs(t *testing.T) {
	setupSettingTestDB(t)
	db := database.GetDB()
	master := mkInboundStream(t, 44401, model.AnyTLS, `{"clients":[],"paddingScheme":["stop=8"]}`, `{"network":"tcp","security":"tls"}`)
	fallbacks := &FallbackService{}
	if err := fallbacks.SetByMaster(master.Id, []FallbackInput{{Dest: "8080"}, {Dest: "[::1]:8081", Alpn: "h2"}}); err != nil {
		t.Fatal(err)
	}
	check := func(raw []byte) {
		t.Helper()
		var config conf.AnyTLSServerConfig
		if err := json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		built, err := config.Build()
		if err != nil {
			t.Fatal(err)
		}
		got := built.(*anytls.ServerConfig).Fallbacks
		if len(got) != 2 || got[0].Dest != "8080" || got[0].Alpn != "" || got[1].Dest != "[::1]:8081" || got[1].Alpn != "h2" || len(config.PaddingScheme) != 1 {
			t.Fatalf("fallback/padding configuration lost: %s", raw)
		}
		var settings map[string]any
		if err := json.Unmarshal(raw, &settings); err != nil {
			t.Fatal(err)
		}
		for _, entry := range settings["fallbacks"].([]any) {
			for key := range entry.(map[string]any) {
				if key != "dest" && key != "alpn" {
					t.Fatalf("unsupported fallback field: %s", key)
				}
			}
		}
	}
	svc := &InboundService{}
	for _, local := range []bool{false, true} {
		var runtime *model.Inbound
		var err error
		if local {
			runtime, err = svc.buildInboundForLocalRuntime(db, master)
		} else {
			runtime, err = svc.buildInboundForNodePush(db, master)
		}
		if err != nil {
			t.Fatal(err)
		}
		check(runtime.GenXrayInboundConfig().Settings)
	}
	config, err := (&XrayService{}).GetXrayConfig()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, inbound := range config.InboundConfigs {
		if inbound.Tag == master.Tag {
			check(inbound.Settings)
			found = true
		}
	}
	if !found {
		t.Fatal("AnyTLS inbound omitted")
	}
	if err := fallbacks.SetByMaster(master.Id, nil); err != nil {
		t.Fatal(err)
	}
	runtime, err := svc.buildInboundForNodePush(db, master)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(runtime.Settings), &settings); err != nil {
		t.Fatal(err)
	}
	if _, exists := settings["fallbacks"]; exists {
		t.Fatal("cleared fallbacks remained enabled")
	}
}

func TestAnyTLSFallbackRejectsInvalidRowsAtomically(t *testing.T) {
	setupBulkDB(t)
	db := database.GetDB()
	master := mkInboundStream(t, 44402, model.AnyTLS, `{"clients":[]}`, `{"network":"tcp","security":"tls"}`)
	child := mkInboundStream(t, 44403, model.VLESS, `{"clients":[]}`, `{"network":"tcp","security":"tls"}`)
	svc := &FallbackService{}
	if err := svc.SetByMaster(master.Id, []FallbackInput{{Dest: "8080"}}); err != nil {
		t.Fatal(err)
	}
	original, err := svc.BuildFallbacksJSON(db, master.Id)
	if err != nil {
		t.Fatal(err)
	}
	for _, rows := range [][]FallbackInput{
		{{Dest: "8081", Name: "example.com"}}, {{Dest: "8081", Path: "/path"}}, {{Dest: "8081", Xver: 1}},
		{{Dest: "8081"}, {Dest: "8082"}}, {{Dest: "http://example.com:80"}}, {{ChildId: child.Id}},
	} {
		if err := svc.SetByMaster(master.Id, rows); err == nil {
			t.Fatalf("invalid fallback accepted: %+v", rows)
		}
		got, err := svc.BuildFallbacksJSON(db, master.Id)
		if err != nil || !reflect.DeepEqual(got, original) {
			t.Fatal("failed update replaced existing fallback", got, err)
		}
	}
	child.StreamSettings = `{"network":"tcp","security":"none","tcpSettings":{"acceptProxyProtocol":true}}`
	if err := db.Save(child).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.SetByMaster(master.Id, []FallbackInput{{ChildId: child.Id}}); err == nil {
		t.Fatal("PROXY-dependent child accepted")
	}
	child.StreamSettings = `{"network":"tcp","security":"none"}`
	child.Listen = "::1"
	if err := db.Save(child).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.SetByMaster(master.Id, []FallbackInput{{ChildId: child.Id}}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.BuildFallbacksJSON(db, master.Id)
	if err != nil || len(got) != 1 || got[0]["dest"] != "[::1]:44403" || len(got[0]) != 1 {
		t.Fatal("derived backend differs", got, err)
	}
}
