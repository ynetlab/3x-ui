package panelcert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

type DNSChallenge interface {
	Present(context.Context, string, string) (string, error)
	Wait(context.Context, string, string) error
	Clean(context.Context, string) error
}

// OrderState is persisted before finalization. Retrying a lost finalize or
// download response retrieves the same order and key instead of issuing again.
type OrderState struct {
	URL        string `json:"url"`
	PrivateKey string `json:"privateKey"`
	CSR        []byte `json:"csr"`
}

// Issue uses the project's existing Go ACME client. DNS credentials remain on
// the master; only the finished certificate and key are deployed to a slave.
func Issue(ctx context.Context, account crypto.Signer, email, directory string, client *http.Client, dns DNSChallenge, domains []string, state *OrderState, save func(OrderState) error) (Bundle, error) {
	c := &acme.Client{Key: account, DirectoryURL: directory, HTTPClient: client, UserAgent: "3x-ui/node-panel-certificate"}
	_, registrationErr := c.Register(ctx, &acme.Account{Contact: []string{"mailto:" + email}}, acme.AcceptTOS)
	if registrationErr != nil && !errors.Is(registrationErr, acme.ErrAccountAlreadyExists) {
		return Bundle{}, errors.New("acme_account_failed")
	}
	if errors.Is(registrationErr, acme.ErrAccountAlreadyExists) {
		if _, err := c.UpdateReg(ctx, &acme.Account{Contact: []string{"mailto:" + email}}); err != nil {
			return Bundle{}, errors.New("acme_account_failed")
		}
	}
	var order *acme.Order
	var err error
	if state.URL != "" {
		order, err = c.GetOrder(ctx, state.URL)
		if err != nil {
			return Bundle{}, errors.New("acme_order_failed")
		}
		if order.Status == acme.StatusInvalid || order.Status == acme.StatusExpired {
			*state = OrderState{}
			if err := save(*state); err != nil {
				return Bundle{}, err
			}
			return Bundle{}, errors.New("acme_order_failed")
		}
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return Bundle{}, err
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: domains}, key)
		if err != nil {
			return Bundle{}, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return Bundle{}, err
		}
		order, err = c.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
		if err != nil {
			return Bundle{}, errors.New("acme_order_failed")
		}
		*state = OrderState{URL: order.URI, PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), CSR: csr}
		if err := save(*state); err != nil {
			return Bundle{}, err
		}
	}
	if state.PrivateKey == "" || len(state.CSR) == 0 {
		return Bundle{}, errors.New("acme_order_failed")
	}
	for _, uri := range order.AuthzURLs {
		auth, err := c.GetAuthorization(ctx, uri)
		if err != nil {
			return Bundle{}, errors.New("acme_authorization_failed")
		}
		if auth.Status == acme.StatusValid {
			continue
		}
		var challenge *acme.Challenge
		for _, candidate := range auth.Challenges {
			if candidate.Type == "dns-01" {
				challenge = candidate
				break
			}
		}
		if challenge == nil {
			return Bundle{}, errors.New("acme_dns01_unavailable")
		}
		value, err := c.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return Bundle{}, errors.New("acme_challenge_failed")
		}
		name := "_acme-challenge." + strings.TrimPrefix(auth.Identifier.Value, "*.")
		id, err := dns.Present(ctx, name, value)
		if err != nil {
			return Bundle{}, err
		}
		// Cleanup is also recorded durably by the provider, so cancellation or
		// process interruption can be recovered on the next worker cycle.
		err = dns.Wait(ctx, name, value)
		if err == nil {
			_, err = c.Accept(ctx, challenge)
		}
		if err == nil {
			_, err = c.WaitAuthorization(ctx, uri)
		}
		cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		cleanErr := dns.Clean(cleanCtx, id)
		cancel()
		if err != nil {
			return Bundle{}, errors.New("acme_authorization_failed")
		}
		if cleanErr != nil {
			return Bundle{}, cleanErr
		}
	}
	order, err = c.WaitOrder(ctx, order.URI)
	if err != nil {
		return Bundle{}, errors.New("acme_order_failed")
	}
	var chain [][]byte
	if order.Status == acme.StatusValid {
		chain, err = c.FetchCert(ctx, order.CertURL, true)
	} else {
		chain, _, err = c.CreateCertFromOrder(ctx, order, state.CSR, true)
	}
	if err != nil {
		return Bundle{}, errors.New("acme_finalize_failed")
	}
	return Bundle{Certificate: EncodeChain(chain), PrivateKey: state.PrivateKey, Domains: append([]string(nil), domains...)}, nil
}
