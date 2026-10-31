package service

import (
	"encoding/json"
	"fmt"
)

func validateRealityNonPQMode(streamSettings string) error {
	if streamSettings == "" {
		return nil
	}
	var stream struct {
		Security        string          `json:"security"`
		RealitySettings json.RawMessage `json:"realitySettings"`
	}
	if err := json.Unmarshal([]byte(streamSettings), &stream); err != nil || stream.Security != "reality" {
		return nil
	}
	if len(stream.RealitySettings) == 0 {
		return nil
	}
	var reality struct {
		NonPQMode string `json:"nonPQMode"`
	}
	if err := json.Unmarshal(stream.RealitySettings, &reality); err != nil {
		return fmt.Errorf("invalid REALITY settings: %w", err)
	}
	switch reality.NonPQMode {
	case "", "none", "legacy", "all":
		return nil
	default:
		return fmt.Errorf("invalid REALITY nonPQMode %q: expected none, legacy or all", reality.NonPQMode)
	}
}
