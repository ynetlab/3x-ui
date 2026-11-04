package accessstats

import (
	_ "embed"
	"encoding/json"
	"hash/fnv"
	"strings"
)

//go:embed policy.json
var policyJSON []byte

type catalogPolicy struct {
	Excluded         map[string][]string `json:"excluded"`
	Aliases          map[string]string   `json:"aliases"`
	RegionalSuffixes []string            `json:"regionalSuffixes"`
	Vendors          []string            `json:"vendors"`
	Names            map[string]string   `json:"names"`
	SharedDomains    []string            `json:"sharedDomains"`
}

var policy = func() catalogPolicy {
	var value catalogPolicy
	if err := json.Unmarshal(policyJSON, &value); err != nil {
		panic(err)
	}
	return value
}()

var excludedCategories = func() map[string]string {
	values := map[string]string{}
	for reason, codes := range policy.Excluded {
		for _, code := range codes {
			values[code] = reason
		}
	}
	return values
}()

var vendorCategories = func() map[string]bool {
	values := map[string]bool{}
	for _, code := range policy.Vendors {
		values[code] = true
	}
	return values
}()

var sharedDomains = func() map[string]bool {
	values := map[string]bool{}
	for _, host := range policy.SharedDomains {
		values[host] = true
	}
	return values
}()

func categoryExclusion(code string) string {
	for _, prefix := range []string{"category-", "geolocation-", "tld-"} {
		if strings.HasPrefix(code, prefix) {
			return "aggregate"
		}
	}
	if reason := excludedCategories[code]; reason != "" {
		return reason
	}
	if len(code) == 0 || len(code) > 64 {
		return "invalid"
	}
	for _, character := range code {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '!' {
			continue
		}
		return "invalid"
	}
	return ""
}

func canonicalCategory(code string, available map[string]bool) string {
	if alias := policy.Aliases[code]; alias != "" {
		return alias
	}
	for _, suffix := range append([]string{"-dev"}, policy.RegionalSuffixes...) {
		if base, ok := strings.CutSuffix(code, suffix); ok && available[base] && categoryExclusion(base) == "" {
			return base
		}
	}
	return code
}

// ApplicationMetadata is computed only for rows returned by a query, so an
// overview does not repeatedly transmit the entire thousand-service catalog.
func ApplicationMetadata(id string) Application {
	for _, app := range Applications {
		if app.ID == id {
			return Application{ID: app.ID, Name: app.Name, Color: app.Color}
		}
	}
	name := policy.Names[id]
	if name == "" {
		name = id
	}
	palette := [...]string{"#1677ff", "#13a8a8", "#722ed1", "#d46b08", "#08979c", "#531dab", "#c41d7f", "#237804"}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(id))
	return Application{ID: id, Name: name, Color: palette[int(hash.Sum32())%len(palette)]}
}
