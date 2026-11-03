package service

import (
	"errors"
	"regexp"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/crypto/nodetoken"
	"github.com/mhsanaei/3x-ui/v3/internal/web/entity"
)

const cloudflareTokenKey = "cloudflareApiToken"

var cloudflareIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (s *SettingService) GetCloudflareAPIToken() (string, error) {
	value, err := s.getString(cloudflareTokenKey)
	if err != nil {
		return "", err
	}
	return decodeCloudflareToken(value)
}

func decodeCloudflareToken(value string) (string, error) {
	if nodetoken.IsEncrypted(value) && !nodetoken.Enabled() {
		return "", errors.New("cloudflare_token_unavailable")
	}
	plain, err := nodetoken.DecryptBound([]byte("settings/"+cloudflareTokenKey), value)
	if err != nil {
		return "", errors.New("cloudflare_token_unavailable")
	}
	return plain, nil
}

func (s *SettingService) prepareCloudflareSettings(all *entity.AllSetting, clears SecretClears) error {
	all.CloudflareZoneID = strings.ToLower(strings.TrimSpace(all.CloudflareZoneID))
	all.CloudflareAPIToken = strings.TrimSpace(all.CloudflareAPIToken)
	if clears.CloudflareAPIToken {
		all.CloudflareAPIToken = ""
	} else if all.CloudflareAPIToken == "" {
		value, err := s.GetCloudflareAPIToken()
		if err != nil {
			return err
		}
		all.CloudflareAPIToken = value
	}
	if all.CloudflareZoneID != "" && !cloudflareIDPattern.MatchString(all.CloudflareZoneID) {
		return errors.New("invalid_cloudflare_zone_id")
	}
	if len(all.CloudflareAPIToken) > 512 {
		return errors.New("invalid_cloudflare_api_token")
	}
	for _, c := range all.CloudflareAPIToken {
		if c < 0x21 || c > 0x7e {
			return errors.New("invalid_cloudflare_api_token")
		}
	}
	// The global token belongs to the managing panel. Normal settings saves on
	// unconfigured slaves still work with the two empty default values.
	if all.CloudflareZoneID != "" || all.CloudflareAPIToken != "" {
		role, err := s.GetPanelRole()
		if err != nil {
			return err
		}
		if role != PanelRoleMaster {
			oldZone, err := s.getString("cloudflareZoneId")
			if err != nil {
				return err
			}
			oldToken, err := s.GetCloudflareAPIToken()
			if err != nil {
				return err
			}
			if all.CloudflareZoneID != "" && all.CloudflareZoneID != oldZone || all.CloudflareAPIToken != "" && all.CloudflareAPIToken != oldToken {
				return errors.New("cloudflare_requires_master")
			}
		}
	}
	return nil
}
