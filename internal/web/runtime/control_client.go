package runtime

import (
	"crypto/tls"
	"errors"
	"net/http"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/netproxy"
)

type ControlClientTLSProvider func(*model.Node) (*tls.Config, error)

var controlProvider struct {
	sync.RWMutex
	load ControlClientTLSProvider
}

func SetControlClientTLSProvider(provider ControlClientTLSProvider) {
	controlProvider.Lock()
	controlProvider.load = provider
	controlProvider.Unlock()
	InvalidateMasterClientConnections()
}

func controlNodeHTTPClient(node *model.Node, proxyURL string) (*http.Client, error) {
	if node.Scheme != "https" || node.TlsVerifyMode != "mtls" || node.Guid == "" {
		return nil, errors.New("paired node requires HTTPS, mTLS and a GUID")
	}
	build := func() (idleClosingRoundTripper, error) {
		controlProvider.RLock()
		load := controlProvider.load
		controlProvider.RUnlock()
		if load == nil {
			return nil, errors.New("control client TLS provider is not configured")
		}
		config, err := load(node)
		if err != nil {
			return nil, err
		}
		if proxyURL == "" {
			return newNodeTransport(config), nil
		}
		client, err := netproxy.NewHTTPClient(proxyURL, remoteHTTPTimeout)
		if err != nil {
			return nil, err
		}
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			return nil, errors.New("control proxy transport cannot configure TLS")
		}
		transport.TLSClientConfig = config
		return transport, nil
	}
	transport, err := newCredentialRotatingTransport(build)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: transport, Timeout: remoteHTTPTimeout}, nil
}
