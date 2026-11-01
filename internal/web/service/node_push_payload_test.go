package service

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

func payloadClientEmails(t *testing.T, settings string) []string {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal([]byte(settings), &parsed); err != nil {
		t.Fatalf("settings not valid json: %v", err)
	}
	raw, _ := parsed["clients"].([]any)
	out := make([]string, 0, len(raw))
	for _, c := range raw {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if email, _ := cm["email"].(string); email != "" {
			out = append(out, email)
		}
	}
	return out
}

// Stripping disabled clients from a node push made the node delete the row and
// the master mirror that back: every depleted client destroyed, not disabled.
func TestNodePushKeepsDisabledClientsLocalPushStripsThem(t *testing.T) {
	setupBulkDB(t)
	svc := &InboundService{}
	db := database.GetDB()

	clients := []model.Client{
		{Email: "alive@x", ID: "11111111-1111-1111-1111-111111111111", Enable: true},
		{Email: "quota@x", ID: "22222222-2222-2222-2222-222222222222", Enable: true},
	}
	ib := mkInbound(t, 30301, model.VLESS, clientsSettings(t, clients))

	for _, c := range clients {
		row := &xray.ClientTraffic{InboundId: ib.Id, Email: c.Email, Enable: true}
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seed traffic %s: %v", c.Email, err)
		}
	}
	if err := db.Model(xray.ClientTraffic{}).
		Where("email = ?", "quota@x").
		Update("enable", false).Error; err != nil {
		t.Fatalf("deplete quota@x: %v", err)
	}

	t.Run("node payload keeps the depletion-disabled client", func(t *testing.T) {
		built, err := svc.buildInboundForNodePush(db, ib)
		if err != nil {
			t.Fatalf("buildInboundForNodePush: %v", err)
		}
		got := payloadClientEmails(t, built.Settings)
		if len(got) != 2 {
			t.Fatalf("node push dropped a client: got %v, want both alive@x and quota@x", got)
		}
	})

	t.Run("local xray payload still strips it", func(t *testing.T) {
		built, err := svc.buildInboundForLocalRuntime(db, ib)
		if err != nil {
			t.Fatalf("buildInboundForLocalRuntime: %v", err)
		}
		got := payloadClientEmails(t, built.Settings)
		if len(got) != 1 || got[0] != "alive@x" {
			t.Fatalf("local runtime payload = %v, want only alive@x", got)
		}
	})
}

func TestAddInbound_AnyTLSDeploysToNode(t *testing.T) {
	setupConflictDB(t)
	node := seedVersionedNode(t, "dev+anytls")
	svc := &InboundService{}
	inbound := &model.Inbound{
		Tag: "anytls-node", Enable: true, Listen: "0.0.0.0", Port: 44300,
		Protocol: model.AnyTLS, NodeID: &node.Id,
		Settings:       `{"clients":[{"id":"8a4f0c7e-1d2b-4c3a-9e5f-6a7b8c9d0e1f","email":"anytls@node","enable":true}],"paddingScheme":"stop=8"}`,
		StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"node.example.com","certificates":[{"certificateFile":"/node/cert.pem","keyFile":"/node/key.pem"}]}}`,
	}
	created, _, err := svc.AddInbound(inbound)
	if err != nil {
		t.Fatalf("AddInbound: %v", err)
	}
	var stored model.Inbound
	if err := database.GetDB().First(&stored, created.Id).Error; err != nil {
		t.Fatalf("read created inbound: %v", err)
	}
	if stored.NodeID == nil || *stored.NodeID != node.Id || stored.Protocol != model.AnyTLS {
		t.Fatalf("stored inbound: nodeId = %v, protocol = %s", stored.NodeID, stored.Protocol)
	}
	payload, err := svc.buildInboundForNodePush(database.GetDB(), &stored)
	if err != nil {
		t.Fatalf("buildInboundForNodePush: %v", err)
	}
	if payload.Protocol != model.AnyTLS || payload.StreamSettings != inbound.StreamSettings {
		t.Fatalf("node payload lost AnyTLS protocol or stream settings: %+v", payload)
	}
	var settings struct {
		Clients       []model.Client `json:"clients"`
		PaddingScheme string         `json:"paddingScheme"`
	}
	if err := json.Unmarshal([]byte(payload.Settings), &settings); err != nil {
		t.Fatalf("decode node settings: %v", err)
	}
	if len(settings.Clients) != 1 || settings.Clients[0].ID != "8a4f0c7e-1d2b-4c3a-9e5f-6a7b8c9d0e1f" || settings.Clients[0].Email != "anytls@node" || settings.PaddingScheme != "stop=8" {
		t.Fatalf("node payload lost AnyTLS credentials or padding: %+v", settings)
	}
}
