package accessstats

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/mhsanaei/3x-ui/v3/internal/xray/geodata"
)

// Bounds fail a rebuild atomically instead of silently truncating categories.
// The existing classifier remains usable when a replacement exceeds them.
const (
	maxApplicationRules         = 250000
	maxApplicationGroups        = 8192
	maxRuleMemberships          = 1000000
	maxRuleHostBytes            = 16 << 20
	applicationMask      uint32 = 0xffff
)

var ErrClassifierCapacity = errors.New("application rules exceed resource limits")

type ClassifierReport struct {
	SourceGroups   int                 `json:"sourceGroups"`
	Applications   int                 `json:"applications"`
	Rules          int                 `json:"rules"`
	AmbiguousRules int                 `json:"ambiguousRules"`
	Excluded       map[string][]string `json:"excluded"`
	Merged         map[string]string   `json:"merged"`
	NoRules        []string            `json:"noRules"`
	Shadowed       []string            `json:"shadowed"`
}

// Each dictionary stores an integer target, not duplicated application strings.
// A lookup probes the hostname and its parents; its cost depends on hostname
// depth, never the number of services. Published classifiers are immutable.
type Classifier struct {
	suffix  map[string]uint32
	exact   map[string]uint32
	ids     []string
	Version string
	Report  ClassifierReport
}

type applicationRules struct {
	id    string
	tier  uint32
	rules []uint32
}
type ruleOwners struct {
	first    uint16
	others   []uint16
	explicit uint16
}
type ruleCompiler struct {
	classifier  *Classifier
	apps        []applicationRules
	byID        map[string]uint16
	rules       []ruleOwners
	memberships int
	hostBytes   int
	subsets     map[uint32]bool
}

func newRuleCompiler() *ruleCompiler {
	return &ruleCompiler{
		classifier: &Classifier{suffix: map[string]uint32{}, exact: map[string]uint32{}, Report: ClassifierReport{Excluded: map[string][]string{}, Merged: map[string]string{}, NoRules: []string{}, Shadowed: []string{}}},
		apps:       []applicationRules{{id: "unknown"}}, byID: map[string]uint16{}, subsets: map[uint32]bool{},
	}
}

func (b *ruleCompiler) application(id string) (uint16, error) {
	if index, ok := b.byID[id]; ok {
		return index, nil
	}
	if len(b.apps) >= maxApplicationGroups {
		return 0, ErrClassifierCapacity
	}
	index := uint16(len(b.apps))
	tier := uint32(2)
	if vendorCategories[id] {
		tier = 1
	}
	b.apps = append(b.apps, applicationRules{id: id, tier: tier})
	b.byID[id] = index
	return index, nil
}

func (b *ruleCompiler) add(host string, app uint16, exact, explicit bool) error {
	host = Host(host)
	if host == "" || sharedDomains[host] {
		return nil
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(host); err != nil {
		return nil
	}
	target := b.classifier.suffix
	if exact {
		target = b.classifier.exact
	}
	ruleID, exists := target[host]
	if !exists {
		if len(b.rules) >= maxApplicationRules || b.hostBytes+len(host) > maxRuleHostBytes {
			return ErrClassifierCapacity
		}
		b.hostBytes += len(host)
		b.rules = append(b.rules, ruleOwners{first: app})
		ruleID = uint32(len(b.rules))
		target[host] = ruleID
	} else {
		owners := &b.rules[ruleID-1]
		if owners.first != app && !slices.Contains(owners.others, app) {
			owners.others = append(owners.others, app)
		}
	}
	if explicit {
		b.rules[ruleID-1].explicit = app
	}
	b.memberships++
	if b.memberships > maxRuleMemberships {
		return ErrClassifierCapacity
	}
	b.apps[app].rules = append(b.apps[app].rules, ruleID)
	return nil
}

func (b *ruleCompiler) addBuiltins() error {
	for _, app := range Applications {
		index, err := b.application(app.ID)
		if err != nil {
			return err
		}
		for _, host := range app.Domains {
			if err := b.add(host, index, false, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func BuiltinClassifier() *Classifier {
	b := newRuleCompiler()
	if err := b.addBuiltins(); err != nil {
		panic(err)
	}
	return b.finish()
}

func NewClassifier(ctx context.Context, store *geodata.Store, name string) (*Classifier, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b := newRuleCompiler()
	if err := b.addBuiltins(); err != nil {
		return nil, err
	}
	page, err := store.Categories(name, "", 0, 0)
	if err != nil {
		return nil, err
	}
	b.classifier.Report.SourceGroups = len(page.Items)
	available := make(map[string]bool, len(page.Items))
	for _, category := range page.Items {
		available[category.Code] = true
	}
	selected := map[string]uint16{}
	for _, category := range page.Items {
		code := category.Code
		if reason := categoryExclusion(code); reason != "" {
			b.classifier.Report.Excluded[reason] = append(b.classifier.Report.Excluded[reason], code)
			continue
		}
		id := canonicalCategory(code, available)
		if id != code {
			b.classifier.Report.Merged[code] = id
		}
		index, err := b.application(id)
		if err != nil {
			return nil, err
		}
		selected[code] = index
	}
	err = store.WalkSiteRules(ctx, name, func(code string) bool { _, ok := selected[code]; return ok }, func(code string, rule geodata.GeoEntry, attributes []string) error {
		for _, attribute := range attributes {
			if attribute == "ads" {
				return nil
			}
		}
		return b.add(rule.Value, selected[code], rule.Kind == "full", false)
	})
	if err != nil {
		return nil, err
	}
	return b.finish(), nil
}

func (b *ruleCompiler) isSubset(small, big uint16) bool {
	key := uint32(small)<<16 | uint32(big)
	if cached, ok := b.subsets[key]; ok {
		return cached
	}
	child, parent := b.apps[small].rules, b.apps[big].rules
	result := len(child) <= len(parent)
	if result {
		for _, id := range child {
			if _, found := slices.BinarySearch(parent, id); !found {
				result = false
				break
			}
		}
	}
	// Limit the build-only relationship cache even for adversarial overlaps.
	if len(b.subsets) < 32768 {
		b.subsets[key] = result
	}
	return result
}

func (b *ruleCompiler) resolve(rule ruleOwners) uint32 {
	if rule.explicit != 0 {
		return uint32(rule.explicit) | 3<<16
	}
	winner := rule.first
	consider := func(candidate uint16) {
		current, next := b.apps[winner], b.apps[candidate]
		if next.tier > current.tier || next.tier == current.tier && (len(next.rules) < len(current.rules) || len(next.rules) == len(current.rules) && next.id < current.id) {
			winner = candidate
		}
	}
	for _, owner := range rule.others {
		consider(owner)
	}
	tier := b.apps[winner].tier
	check := func(owner uint16) bool { return b.apps[owner].tier < tier || b.isSubset(winner, owner) }
	if !check(rule.first) {
		return tier << 16
	}
	for _, owner := range rule.others {
		if !check(owner) {
			return tier << 16
		}
	}
	return uint32(winner) | tier<<16
}

func (b *ruleCompiler) finish() *Classifier {
	c := b.classifier
	c.ids = make([]string, len(b.apps))
	for i := range b.apps {
		slices.Sort(b.apps[i].rules)
		b.apps[i].rules = slices.Compact(b.apps[i].rules)
		c.ids[i] = b.apps[i].id
	}
	resolved := make([]uint32, len(b.rules))
	for i, rule := range b.rules {
		resolved[i] = b.resolve(rule)
	}
	for _, dictionary := range []map[string]uint32{c.suffix, c.exact} {
		for host, id := range dictionary {
			dictionary[host] = resolved[id-1]
		}
	}
	for host, exact := range c.exact {
		if suffix, ok := c.suffix[host]; ok && suffix>>16 > exact>>16 {
			c.exact[host] = suffix
		}
	}
	used := make([]bool, len(b.apps))
	hash := sha256.New()
	_, _ = hash.Write([]byte(CatalogVersion))
	for i, dictionary := range []map[string]uint32{c.suffix, c.exact} {
		hosts := make([]string, 0, len(dictionary))
		for host := range dictionary {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)
		for _, host := range hosts {
			id := dictionary[host] & applicationMask
			used[id] = true
			c.Report.Rules++
			if id == 0 {
				c.Report.AmbiguousRules++
			}
			_, _ = hash.Write([]byte(strconv.Itoa(i) + "\x00" + host + "\x00" + c.ids[id] + "\x00"))
		}
	}
	c.Version = hex.EncodeToString(hash.Sum(nil))
	for i, app := range b.apps {
		if i == 0 {
			continue
		}
		if used[i] {
			c.Report.Applications++
		} else if len(app.rules) == 0 {
			c.Report.NoRules = append(c.Report.NoRules, app.id)
		} else {
			c.Report.Shadowed = append(c.Report.Shadowed, app.id)
		}
	}
	sort.Strings(c.Report.NoRules)
	sort.Strings(c.Report.Shadowed)
	return c
}

func (c *Classifier) Match(host string) string {
	host = Host(host)
	if host == "" {
		return "unknown"
	}
	if app, ok := c.exact[host]; ok {
		return c.ids[app&applicationMask]
	}
	for {
		if app, ok := c.suffix[host]; ok {
			return c.ids[app&applicationMask]
		}
		index := strings.IndexByte(host, '.')
		if index < 0 {
			return "unknown"
		}
		host = host[index+1:]
	}
}

func (c *Classifier) Catalog() []Application {
	used := make([]bool, len(c.ids))
	for _, dictionary := range []map[string]uint32{c.suffix, c.exact} {
		for _, app := range dictionary {
			used[app&applicationMask] = true
		}
	}
	result := make([]Application, 0, c.Report.Applications)
	for index, id := range c.ids {
		if index != 0 && used[index] {
			result = append(result, ApplicationMetadata(id))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
