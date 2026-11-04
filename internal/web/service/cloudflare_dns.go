package service

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"github.com/mhsanaei/3x-ui/v3/internal/cloudflare"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

type CloudflareDNSError struct {
	Status         int
	Code, RecordID string
}

func (e *CloudflareDNSError) Error() string  { return e.Code }
func dnsError(status int, code string) error { return &CloudflareDNSError{Status: status, Code: code} }

var cloudflareDNSGate = make(chan struct{}, 1)

func lockCloudflareDNS(ctx context.Context) error {
	select {
	case cloudflareDNSGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func dnsDB() *gorm.DB { return database.GetDB().Session(&gorm.Session{Logger: logger.Discard}) }

type CloudflareDNSService struct {
	newClient func(string) *cloudflare.Client
}
type DNSRecordInput struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied *bool  `json:"proxied"`
}
type DNSRecordView struct {
	cloudflare.Record
	Bound         bool   `json:"bound"`
	OwnerNodeID   int    `json:"ownerNodeId,omitempty"`
	Missing       bool   `json:"missing"`
	Changed       bool   `json:"changed"`
	LastSyncError string `json:"lastSyncError"`
	LastSyncedAt  int64  `json:"lastSyncedAt"`
}
type NodeDNSRecords struct {
	ZoneID      string             `json:"zoneId"`
	ZoneName    string             `json:"zoneName"`
	NodeID      int                `json:"nodeId"`
	NodeAddress string             `json:"nodeAddress"`
	Records     []DNSRecordView    `json:"records"`
	PublicIP    model.NodePublicIP `json:"publicIp"`
}
type dnsSession struct {
	node   model.Node
	zone   cloudflare.Zone
	client *cloudflare.Client
}

func (s *CloudflareDNSService) session(ctx context.Context, nodeID int) (*dnsSession, error) {
	role, err := (&SettingService{}).GetPanelRole()
	if err != nil {
		return nil, err
	}
	if role != PanelRoleMaster {
		return nil, dnsError(403, "cloudflare_requires_master")
	}
	if nodeID < 1 {
		return nil, dnsError(400, "invalid_cloudflare_node")
	}
	var node model.Node
	if err := dnsDB().WithContext(ctx).Select("id", "guid", "address", "control_connection").First(&node, nodeID).Error; err != nil {
		if database.IsNotFound(err) {
			return nil, dnsError(404, "cloudflare_node_not_found")
		}
		return nil, err
	}
	var rows []model.Setting
	if err := dnsDB().WithContext(ctx).Where("key IN ?", []string{"cloudflareZoneId", cloudflareTokenKey}).Find(&rows).Error; err != nil {
		return nil, err
	}
	var zone, token string
	for _, row := range rows {
		if row.Key == "cloudflareZoneId" {
			zone = row.Value
		} else {
			token = row.Value
		}
	}
	token, err = decodeCloudflareToken(token)
	if err != nil {
		return nil, err
	}
	if !cloudflare.ValidID(zone) || token == "" {
		return nil, dnsError(409, "cloudflare_not_configured")
	}
	client := cloudflare.New(token, (&SettingService{}).NewProxiedHTTPClient(cloudflare.RequestTimeout))
	if s.newClient != nil {
		client = s.newClient(token)
	}
	info, err := client.Zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	info.Name, err = dnsName(info.Name, false)
	if err != nil {
		return nil, dnsError(502, "cloudflare_invalid_response")
	}
	return &dnsSession{node: node, zone: info, client: client}, nil
}

func dnsName(value string, wildcard bool) (string, error) {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	prefix := ""
	if wildcard && strings.HasPrefix(value, "*.") {
		prefix, value = "*.", strings.TrimPrefix(value, "*.")
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || len(prefix+ascii) > 253 || ascii == "" {
		return "", dnsError(400, "invalid_cloudflare_record_name")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", dnsError(400, "invalid_cloudflare_record_name")
		}
		for _, c := range strings.ToLower(label) {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return "", dnsError(400, "invalid_cloudflare_record_name")
			}
		}
	}
	return prefix + strings.ToLower(ascii), nil
}

func canonicalDNSRecord(record cloudflare.Record, zone string) (cloudflare.Record, error) {
	name, err := dnsName(record.Name, true)
	if err != nil || name != zone && !strings.HasSuffix(name, "."+zone) {
		return record, dnsError(400, "cloudflare_record_outside_zone")
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(record.Content))
	if err != nil || ip.Zone() != "" {
		return record, dnsError(400, "cloudflare_target_ip_required")
	}
	ip = ip.Unmap()
	if record.Type != "A" && record.Type != "AAAA" || record.Type == "A" && !ip.Is4() || record.Type == "AAAA" && !ip.Is6() {
		return record, dnsError(400, "invalid_cloudflare_record_type")
	}
	record.Name, record.Content = name, ip.String()
	if record.Proxied {
		record.TTL = 1
	}
	if record.TTL != 1 && (record.TTL < 30 || record.TTL > 86400) {
		return record, dnsError(400, "invalid_cloudflare_record_ttl")
	}
	return record, nil
}

func dnsInput(input DNSRecordInput, current cloudflare.Record, nodeAddress, zone string) (cloudflare.Record, error) {
	if input.TTL < 0 {
		return current, dnsError(400, "invalid_cloudflare_record_ttl")
	}
	r := current
	if input.Name != "" {
		r.Name = input.Name
	}
	if r.Name == "@" {
		r.Name = zone
	}
	if input.Content != "" {
		r.Content = input.Content
	}
	if r.Content == "" {
		r.Content = strings.Trim(strings.TrimSpace(nodeAddress), "[]")
	}
	if input.Type != "" {
		r.Type = strings.ToUpper(strings.TrimSpace(input.Type))
	}
	if r.Type == "" {
		if ip, err := netip.ParseAddr(r.Content); err == nil && ip.Unmap().Is4() {
			r.Type = "A"
		} else {
			r.Type = "AAAA"
		}
	}
	if input.TTL != 0 {
		r.TTL = input.TTL
	}
	if r.TTL == 0 {
		r.TTL = 1
	}
	if input.Proxied != nil {
		r.Proxied = *input.Proxied
	}
	return canonicalDNSRecord(r, zone)
}

func dnsWire(r cloudflare.Record) map[string]any {
	return map[string]any{"name": r.Name, "type": r.Type, "content": r.Content, "ttl": r.TTL, "proxied": r.Proxied}
}

func (d *dnsSession) find(ctx context.Context, query url.Values) ([]cloudflare.Record, error) {
	query.Set("per_page", "100")
	query.Set("match", "all")
	query.Set("order", "name")
	result := []cloudflare.Record{}
	for page := 1; page <= 100; page++ {
		query.Set("page", strconv.Itoa(page))
		items, err := d.client.List(ctx, d.zone.ID, query)
		if err != nil {
			return nil, err
		}
		result = append(result, items.Records...)
		if items.TotalPages > 0 && page >= items.TotalPages || len(items.Records) < 100 {
			return result, nil
		}
	}
	return nil, dnsError(502, "cloudflare_record_limit_exceeded")
}

func (d *dnsSession) binding(ctx context.Context, id string) (model.NodeDNSBinding, error) {
	if !cloudflare.ValidID(id) {
		return model.NodeDNSBinding{}, dnsError(400, "invalid_cloudflare_record_id")
	}
	var b model.NodeDNSBinding
	err := dnsDB().WithContext(ctx).Where("zone_id = ? AND record_id = ? AND node_id = ? AND node_guid = ?", d.zone.ID, id, d.node.Id, d.node.Guid).First(&b).Error
	if database.IsNotFound(err) {
		return b, dnsError(404, "cloudflare_record_not_bound")
	}
	return b, err
}

func (d *dnsSession) ensureOwner(ctx context.Context, id string) error {
	var b model.NodeDNSBinding
	err := dnsDB().WithContext(ctx).Where("zone_id = ? AND record_id = ?", d.zone.ID, id).First(&b).Error
	if database.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if b.NodeID == d.node.Id && b.NodeGUID == d.node.Guid {
		return nil
	}
	live, err := dnsBindingOwnerLive(dnsDB().WithContext(ctx), b)
	if err != nil {
		return err
	}
	if live {
		return dnsError(409, "cloudflare_record_owned_by_other_node")
	}
	return nil
}

func (d *dnsSession) saveBinding(ctx context.Context, record cloudflare.Record) (DNSRecordView, error) {
	view := DNSRecordView{Record: record}
	err := dnsDB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&model.Node{}).Where("id = ? AND guid = ?", d.node.Id, d.node.Guid).Count(&count).Error; err != nil {
			return err
		}
		if count != 1 {
			return dnsError(409, "cloudflare_node_changed")
		}
		b := model.NodeDNSBinding{NodeID: d.node.Id, NodeGUID: d.node.Guid, ZoneID: d.zone.ID, RecordID: record.ID, Name: record.Name, Type: record.Type, Content: record.Content, TTL: record.TTL, Proxied: record.Proxied}
		if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "zone_id"}, {Name: "record_id"}}, DoNothing: true}).Create(&b).Error; err != nil {
			return err
		}
		var existing model.NodeDNSBinding
		if err := tx.Where("zone_id = ? AND record_id = ?", d.zone.ID, record.ID).First(&existing).Error; err != nil {
			return err
		}
		if existing.NodeID != d.node.Id || existing.NodeGUID != d.node.Guid {
			live, err := dnsBindingOwnerLive(tx, existing)
			if err != nil {
				return err
			}
			if live {
				return dnsError(409, "cloudflare_record_owned_by_other_node")
			}
		}
		return tx.Model(&existing).Updates(map[string]any{"node_id": b.NodeID, "node_guid": b.NodeGUID, "name": b.Name, "type": b.Type, "content": b.Content, "ttl": b.TTL, "proxied": b.Proxied, "last_sync_error": ""}).Error
	})
	if err != nil {
		var known *CloudflareDNSError
		if errors.As(err, &known) {
			return view, err
		}
		return view, &CloudflareDNSError{Status: 503, Code: "cloudflare_binding_save_failed", RecordID: record.ID}
	}
	view.Bound, view.OwnerNodeID = true, d.node.Id
	return view, nil
}

func (s *CloudflareDNSService) List(ctx context.Context, nodeID int) (NodeDNSRecords, error) {
	d, err := s.session(ctx, nodeID)
	if err != nil {
		return NodeDNSRecords{}, err
	}
	result := NodeDNSRecords{ZoneID: d.zone.ID, ZoneName: d.zone.Name, NodeID: nodeID, NodeAddress: d.node.Address, Records: []DNSRecordView{}}
	result.PublicIP, err = (&NodeIPService{}).Get(ctx, nodeID)
	if err != nil {
		return result, err
	}
	var bindings []model.NodeDNSBinding
	if err := dnsDB().WithContext(ctx).Where("zone_id = ?", d.zone.ID).Find(&bindings).Error; err != nil {
		return result, err
	}
	owned := map[string]model.NodeDNSBinding{}
	addresses := map[string]bool{}
	if result.PublicIP.IPv4Available {
		addresses[result.PublicIP.IPv4] = true
	}
	if result.PublicIP.IPv6Available {
		addresses[result.PublicIP.IPv6] = true
	}
	if ip, err := netip.ParseAddr(strings.Trim(d.node.Address, "[]")); err == nil && ip.Zone() == "" {
		addresses[ip.Unmap().String()] = true
	}
	for _, b := range bindings {
		if b.NodeID == nodeID && b.NodeGUID == d.node.Guid {
			owned[b.RecordID] = b
			addresses[b.Content] = true
		}
	}
	records := map[string]DNSRecordView{}
	for address := range addresses {
		ip, err := netip.ParseAddr(address)
		if err != nil {
			continue
		}
		kind := "AAAA"
		if ip.Unmap().Is4() {
			kind = "A"
		}
		found, err := d.find(ctx, url.Values{"type": {kind}, "content.exact": {ip.Unmap().String()}})
		if err != nil {
			return result, err
		}
		for _, r := range found {
			if r.Type == kind && r.Content == ip.Unmap().String() {
				records[r.ID] = DNSRecordView{Record: r}
			}
		}
	}
	for id, b := range owned {
		view, ok := records[id]
		if !ok {
			r, err := d.client.Get(ctx, d.zone.ID, id)
			if cloudflare.IsNotFound(err) {
				view = DNSRecordView{Record: cloudflare.Record{ID: id, Name: b.Name, Type: b.Type, Content: b.Content, TTL: b.TTL, Proxied: b.Proxied}, Missing: true}
			} else if err != nil {
				return result, err
			} else {
				view.Record = r
			}
		}
		view.Bound, view.OwnerNodeID = true, nodeID
		view.LastSyncError, view.LastSyncedAt = b.LastSyncError, b.LastSyncedAt
		view.Changed = !view.Missing && (view.Name != b.Name || view.Type != b.Type || view.Content != b.Content || view.TTL != b.TTL || view.Proxied != b.Proxied)
		records[id] = view
	}
	for _, b := range bindings {
		if view, ok := records[b.RecordID]; ok {
			view.OwnerNodeID = b.NodeID
			records[b.RecordID] = view
		}
	}
	for _, view := range records {
		result.Records = append(result.Records, view)
	}
	sort.Slice(result.Records, func(i, j int) bool {
		a, b := result.Records[i], result.Records[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	return result, nil
}

func (s *CloudflareDNSService) Create(ctx context.Context, nodeID int, input DNSRecordInput) (DNSRecordView, error) {
	if err := lockCloudflareDNS(ctx); err != nil {
		return DNSRecordView{}, err
	}
	defer func() { <-cloudflareDNSGate }()
	d, err := s.session(ctx, nodeID)
	if err != nil {
		return DNSRecordView{}, err
	}
	wanted, err := dnsInput(input, cloudflare.Record{}, d.node.Address, d.zone.Name)
	if err != nil {
		return DNSRecordView{}, err
	}
	if wanted.Proxied && d.node.ControlConnection && wanted.Name == d.node.Address {
		return DNSRecordView{}, dnsError(409, "cloudflare_control_domain_requires_dns_only")
	}
	found, err := d.find(ctx, url.Values{"type": {wanted.Type}, "name.exact": {wanted.Name}, "content.exact": {wanted.Content}})
	if err != nil {
		return DNSRecordView{}, err
	}
	var record cloudflare.Record
	for _, r := range found {
		if r.Name == wanted.Name && r.Type == wanted.Type && r.Content == wanted.Content {
			if record.ID != "" {
				return DNSRecordView{}, dnsError(409, "cloudflare_record_ambiguous")
			}
			record = r
		}
	}
	if record.ID != "" {
		if record.Proxied != wanted.Proxied || record.TTL != wanted.TTL {
			return DNSRecordView{}, &CloudflareDNSError{Status: 409, Code: "cloudflare_record_exists", RecordID: record.ID}
		}
		if err := d.ensureOwner(ctx, record.ID); err != nil {
			return DNSRecordView{}, err
		}
	} else {
		record, err = d.client.Create(ctx, d.zone.ID, dnsWire(wanted))
		if err != nil {
			return DNSRecordView{}, err
		}
	}
	if record, err = canonicalDNSRecord(record, d.zone.Name); err != nil {
		return DNSRecordView{}, dnsError(502, "cloudflare_invalid_response")
	}
	return d.saveBinding(ctx, record)
}

func (s *CloudflareDNSService) Bind(ctx context.Context, nodeID int, id, content string) (DNSRecordView, error) {
	if err := lockCloudflareDNS(ctx); err != nil {
		return DNSRecordView{}, err
	}
	defer func() { <-cloudflareDNSGate }()
	if !cloudflare.ValidID(id) {
		return DNSRecordView{}, dnsError(400, "invalid_cloudflare_record_id")
	}
	d, err := s.session(ctx, nodeID)
	if err != nil {
		return DNSRecordView{}, err
	}
	if err := d.ensureOwner(ctx, id); err != nil {
		return DNSRecordView{}, err
	}
	r, err := d.client.Get(ctx, d.zone.ID, id)
	if err != nil {
		return DNSRecordView{}, err
	}
	r, err = canonicalDNSRecord(r, d.zone.Name)
	if err != nil {
		return DNSRecordView{}, err
	}
	if content == "" {
		content = strings.Trim(d.node.Address, "[]")
	}
	ip, err := netip.ParseAddr(content)
	if err != nil || ip.Zone() != "" || ip.Unmap().String() != r.Content {
		return DNSRecordView{}, dnsError(400, "cloudflare_target_ip_mismatch")
	}
	return d.saveBinding(ctx, r)
}

func (s *CloudflareDNSService) Update(ctx context.Context, nodeID int, id string, input DNSRecordInput) (DNSRecordView, error) {
	if err := lockCloudflareDNS(ctx); err != nil {
		return DNSRecordView{}, err
	}
	defer func() { <-cloudflareDNSGate }()
	d, err := s.session(ctx, nodeID)
	if err != nil {
		return DNSRecordView{}, err
	}
	if _, err := d.binding(ctx, id); err != nil {
		return DNSRecordView{}, err
	}
	r, err := d.client.Get(ctx, d.zone.ID, id)
	if err != nil {
		return DNSRecordView{}, err
	}
	// An external replacement with an unsupported type is not ours to overwrite.
	if r.Type != "A" && r.Type != "AAAA" {
		return DNSRecordView{}, dnsError(409, "cloudflare_record_changed")
	}
	wanted, err := dnsInput(input, r, d.node.Address, d.zone.Name)
	if err != nil {
		return DNSRecordView{}, err
	}
	if wanted.Proxied && d.node.ControlConnection && wanted.Name == d.node.Address {
		return DNSRecordView{}, dnsError(409, "cloudflare_control_domain_requires_dns_only")
	}
	patch := map[string]any{}
	if input.Name != "" {
		patch["name"] = wanted.Name
	}
	if input.Type != "" {
		patch["type"] = wanted.Type
	}
	if input.Content != "" {
		patch["content"] = wanted.Content
	}
	if input.TTL != 0 || input.Proxied != nil && *input.Proxied {
		patch["ttl"] = wanted.TTL
	}
	if input.Proxied != nil {
		patch["proxied"] = wanted.Proxied
	}
	if len(patch) == 0 {
		return d.saveBinding(ctx, r)
	}
	updated, err := d.client.Update(ctx, d.zone.ID, id, patch)
	if err != nil {
		return DNSRecordView{}, err
	}
	updated, err = canonicalDNSRecord(updated, d.zone.Name)
	if err != nil {
		return DNSRecordView{}, dnsError(502, "cloudflare_invalid_response")
	}
	actual := dnsWire(updated)
	for key, value := range patch {
		if actual[key] != value {
			return DNSRecordView{}, dnsError(502, "cloudflare_invalid_response")
		}
	}
	return d.saveBinding(ctx, updated)
}

func (s *CloudflareDNSService) SetProxied(ctx context.Context, nodeID int, id string, proxied bool) (DNSRecordView, error) {
	// PATCH preserves unrelated Cloudflare comments, tags and settings.
	return s.Update(ctx, nodeID, id, DNSRecordInput{Proxied: &proxied})
}

func (s *CloudflareDNSService) Delete(ctx context.Context, nodeID int, id string) error {
	if err := lockCloudflareDNS(ctx); err != nil {
		return err
	}
	defer func() { <-cloudflareDNSGate }()
	d, err := s.session(ctx, nodeID)
	if err != nil {
		return err
	}
	b, err := d.binding(ctx, id)
	if err != nil {
		return err
	}
	r, err := d.client.Get(ctx, d.zone.ID, id)
	if err != nil && !cloudflare.IsNotFound(err) {
		return err
	}
	if err == nil {
		if r.Type != "A" && r.Type != "AAAA" {
			return dnsError(409, "cloudflare_record_changed")
		}
		if err := d.client.Delete(ctx, d.zone.ID, id); err != nil && !cloudflare.IsNotFound(err) {
			return err
		}
	}
	return dnsDB().WithContext(ctx).Delete(&b).Error
}
