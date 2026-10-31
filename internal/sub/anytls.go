package sub

import (
	"encoding/json"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
)

func (s *SubJsonService) genAnyTLS(inbound *model.Inbound, stream json_util.RawMessage, client model.Client) json_util.RawMessage {
	outbound := Outbound{
		Protocol: "anytls", Tag: "proxy", StreamSettings: stream,
		Settings: map[string]any{
			"address": inbound.Listen, "port": inbound.Port,
			"password": client.ID, "email": client.Email,
		},
	}
	result, _ := json.MarshalIndent(outbound, "", "  ")
	return result
}
