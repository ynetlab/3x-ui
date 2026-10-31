package model

import "encoding/json"

// UUIDClientsToCore projects the panel's shared client UUID into the credential
// field required by each protocol. Panel settings keep id; core settings keep
// password/auth, without a second stored credential.
func UUIDClientsToCore(protocol Protocol, settings string) string {
	field := "password"
	switch protocol {
	case Trojan, AnyTLS:
	case Hysteria:
		field = "auth"
	default:
		return settings
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal([]byte(settings), &raw) != nil {
		return settings
	}
	var clients []map[string]json.RawMessage
	if json.Unmarshal(raw["clients"], &clients) != nil {
		return settings
	}
	for _, client := range clients {
		id := client["id"]
		delete(client, "id")
		delete(client, "password")
		delete(client, "auth")
		if len(id) > 0 {
			client[field] = id
		}
	}
	if clients == nil {
		clients = []map[string]json.RawMessage{}
	}
	raw["clients"], _ = json.Marshal(clients)
	converted, err := json.Marshal(raw)
	if err != nil {
		return settings
	}
	return string(converted)
}
