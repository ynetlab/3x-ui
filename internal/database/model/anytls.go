package model

import "encoding/json"

// AnyTLSClientsToCore converts panel users to the AnyTLS core's users field.
func AnyTLSClientsToCore(settings string) (string, bool) {
	var raw map[string]json.RawMessage
	if json.Unmarshal([]byte(settings), &raw) != nil {
		return settings, false
	}
	clients, ok := raw["clients"]
	if !ok {
		return settings, false
	}
	type coreUser struct {
		Password string `json:"password"`
		Email    string `json:"email"`
		Level    uint8  `json:"level,omitempty"`
	}
	var users []coreUser
	if json.Unmarshal(clients, &users) != nil {
		return settings, false
	}
	if users == nil {
		users = []coreUser{}
	}
	raw["users"], _ = json.Marshal(users)
	delete(raw, "clients")
	converted, err := json.Marshal(raw)
	if err != nil {
		return settings, false
	}
	return string(converted), true
}
