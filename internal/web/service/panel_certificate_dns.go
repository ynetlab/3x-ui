package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/acme"

	"github.com/mhsanaei/3x-ui/v3/internal/cloudflare"
	"github.com/mhsanaei/3x-ui/v3/internal/crypto/nodetoken"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/panelcert"
	"github.com/mhsanaei/3x-ui/v3/internal/util/netsafe"
)

const (
	settingACMEConfig  = "acmeConfig"
	settingACMEAccount = "acmeAccountKey"
)

var acmeAccountMu sync.Mutex

type ACMEConfig struct {
	Email     string `json:"email"`
	AcceptTOS bool   `json:"acceptTos"`
}

func requireCertificateMaster() error {
	role, err := (&SettingService{}).GetPanelRole()
	if err != nil {
		return err
	}
	if role != PanelRoleMaster {
		return pairingError(403, "certificate_requires_master")
	}
	return nil
}

func (s *NodeCertificateService) Config() (ACMEConfig, error) {
	if err := requireCertificateMaster(); err != nil {
		return ACMEConfig{}, err
	}
	value, err := (&SettingService{}).getString(settingACMEConfig)
	if err != nil {
		return ACMEConfig{}, err
	}
	var config ACMEConfig
	if err = json.Unmarshal([]byte(value), &config); err != nil {
		return config, errors.New("invalid_acme_settings")
	}
	return config, nil
}

func (s *NodeCertificateService) SaveConfig(config ACMEConfig) (ACMEConfig, error) {
	if err := requireCertificateMaster(); err != nil {
		return ACMEConfig{}, err
	}
	config.Email = strings.TrimSpace(config.Email)
	if config.Email != "" {
		address, err := mail.ParseAddress(config.Email)
		if err != nil || address.Address != config.Email || len(config.Email) > 254 {
			return ACMEConfig{}, pairingError(400, "invalid_acme_email")
		}
	}
	if config.AcceptTOS && config.Email == "" {
		return ACMEConfig{}, pairingError(400, "invalid_acme_email")
	}
	data, err := json.Marshal(config)
	if err == nil {
		err = putPairingSetting(pairingDB(), settingACMEConfig, string(data))
	}
	return config, err
}

func (s *NodeCertificateService) configuredDNS(ctx context.Context) (*dnsSession, error) {
	if err := requireCertificateMaster(); err != nil {
		return nil, err
	}
	settings := &SettingService{}
	zone, err := settings.getString("cloudflareZoneId")
	if err != nil {
		return nil, err
	}
	token, err := settings.GetCloudflareAPIToken()
	if err != nil {
		return nil, err
	}
	if !cloudflare.ValidID(zone) || token == "" {
		return nil, dnsError(409, "cloudflare_not_configured")
	}
	client := cloudflare.New(token, settings.NewProxiedHTTPClient(cloudflare.RequestTimeout))
	if s.dnsClient != nil {
		client = s.dnsClient(token)
	}
	info, err := client.Zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	info.Name, err = dnsName(info.Name, false)
	if err != nil {
		return nil, err
	}
	return &dnsSession{zone: info, client: client}, nil
}

func acmeAccountKey() (crypto.Signer, error) {
	acmeAccountMu.Lock()
	defer acmeAccountMu.Unlock()
	value, err := (&SettingService{}).getString(settingACMEAccount)
	if err != nil {
		return nil, err
	}
	if value != "" {
		if nodetoken.IsEncrypted(value) && !nodetoken.Enabled() {
			return nil, errors.New("acme_account_unavailable")
		}
		value, err = nodetoken.DecryptBound([]byte("settings/"+settingACMEAccount), value)
		if err != nil {
			return nil, errors.New("acme_account_unavailable")
		}
		block, _ := pem.Decode([]byte(value))
		if block == nil {
			return nil, errors.New("acme_account_unavailable")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("acme_account_unavailable")
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("acme_account_unavailable")
		}
		return signer, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	value, err = nodetoken.EncryptBound([]byte("settings/"+settingACMEAccount), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	if err != nil {
		return nil, err
	}
	if err := putPairingSetting(pairingDB(), settingACMEAccount, value); err != nil {
		return nil, err
	}
	return key, nil
}

type certificateDNSChallenge struct {
	session *dnsSession
	job     string
	wait    func(context.Context, string, string) error
}

func (d *certificateDNSChallenge) Present(ctx context.Context, name, value string) (string, error) {
	if name != "_acme-challenge."+d.session.zone.Name && !strings.HasSuffix(name, "."+d.session.zone.Name) {
		return "", errors.New("acme_domain_outside_zone")
	}
	row := model.ACMEChallenge{ID: uuid.NewString(), JobID: d.job, ZoneID: d.session.zone.ID, Name: name, Value: value}
	if err := pairingDB().WithContext(ctx).Create(&row).Error; err != nil {
		return "", err
	}
	record, err := d.session.client.Create(ctx, row.ZoneID, map[string]any{"type": "TXT", "name": name, "content": value, "ttl": 60})
	if err != nil {
		return "", err
	}
	if record.Name != name || record.Type != "TXT" || record.Content != value {
		return "", errors.New("cloudflare_invalid_response")
	}
	if err := pairingDB().WithContext(ctx).Model(&row).Update("record_id", record.ID).Error; err != nil {
		return "", err
	}
	return row.ID, nil
}

func (d *certificateDNSChallenge) Clean(ctx context.Context, id string) error {
	var row model.ACMEChallenge
	if err := pairingDB().WithContext(ctx).Where("id = ? AND job_id = ? AND zone_id = ?", id, d.job, d.session.zone.ID).First(&row).Error; err != nil {
		if database.IsNotFound(err) {
			return nil
		}
		return err
	}
	if row.RecordID != "" {
		r, err := d.session.client.Get(ctx, row.ZoneID, row.RecordID)
		if err != nil && !cloudflare.IsNotFound(err) {
			return err
		}
		if err == nil && r.Type == "TXT" && r.Name == row.Name && r.Content == row.Value {
			if err := d.session.client.Delete(ctx, row.ZoneID, row.RecordID); err != nil && !cloudflare.IsNotFound(err) {
				return err
			}
		}
	} else {
		// A lost create response is recovered through the saved unique proof.
		records, err := d.session.find(ctx, url.Values{"type": {"TXT"}, "name.exact": {row.Name}, "content.exact": {row.Value}})
		if err != nil {
			return err
		}
		for _, r := range records {
			if r.Type == "TXT" && r.Name == row.Name && r.Content == row.Value {
				if err := d.session.client.Delete(ctx, row.ZoneID, r.ID); err != nil && !cloudflare.IsNotFound(err) {
					return err
				}
			}
		}
	}
	return pairingDB().WithContext(ctx).Delete(&row).Error
}

func (d *certificateDNSChallenge) Wait(ctx context.Context, name, value string) error {
	if d.wait != nil {
		return d.wait(ctx, name, value)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	nameservers, err := net.DefaultResolver.LookupNS(ctx, d.session.zone.Name)
	if err != nil || len(nameservers) == 0 {
		return errors.New("acme_dns_propagation_failed")
	}
	for {
		ready := true
		for _, ns := range nameservers {
			resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return netsafe.SSRFGuardedDialContext(ctx, network, net.JoinHostPort(ns.Host, "53"))
			}}
			lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
			records, err := resolver.LookupTXT(lookup, name)
			cancel()
			found := false
			for _, record := range records {
				if record == value {
					found = true
				}
			}
			if err != nil || !found {
				ready = false
				break
			}
		}
		if ready {
			return nil
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.New("acme_dns_propagation_failed")
		case <-timer.C:
		}
	}
}

func (s *NodeCertificateService) issue(ctx context.Context, job *model.NodeCertificateJob, d *dnsSession, domains []string) (panelcert.Bundle, error) {
	config, err := s.Config()
	if err != nil {
		return panelcert.Bundle{}, err
	}
	if config.Email == "" || !config.AcceptTOS {
		return panelcert.Bundle{}, pairingError(409, "acme_not_configured")
	}
	account, err := acmeAccountKey()
	if err != nil {
		return panelcert.Bundle{}, err
	}
	provider := &certificateDNSChallenge{session: d, job: job.ID, wait: s.dnsWait}
	var leftovers []model.ACMEChallenge
	if err := pairingDB().Where("job_id = ?", job.ID).Find(&leftovers).Error; err != nil {
		return panelcert.Bundle{}, err
	}
	for _, row := range leftovers {
		if err := provider.Clean(ctx, row.ID); err != nil {
			return panelcert.Bundle{}, err
		}
	}
	client := (&SettingService{}).NewProxiedHTTPClient(30 * time.Second)
	if s.issuer != nil {
		return s.issuer(ctx, domains, provider)
	}
	var state panelcert.OrderState
	if job.ACMEState != "" {
		if nodetoken.IsEncrypted(job.ACMEState) && !nodetoken.Enabled() {
			return panelcert.Bundle{}, errors.New("certificate_key_unavailable")
		}
		data, err := nodetoken.DecryptBound([]byte("node-acme-order/"+job.ID), job.ACMEState)
		if err != nil {
			return panelcert.Bundle{}, errors.New("certificate_key_unavailable")
		}
		if err := json.Unmarshal([]byte(data), &state); err != nil {
			return panelcert.Bundle{}, err
		}
	}
	return panelcert.Issue(ctx, account, config.Email, acme.LetsEncryptURL, client, provider, domains, &state, func(state panelcert.OrderState) error {
		data, err := json.Marshal(state)
		if err != nil {
			return err
		}
		value, err := nodetoken.EncryptBound([]byte("node-acme-order/"+job.ID), string(data))
		if err != nil {
			return err
		}
		return pairingDB().Model(job).Update("acme_state", value).Error
	})
}
