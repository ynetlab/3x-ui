package network

import (
	"crypto/tls"
	"net"
	"sync/atomic"
)

// ReloadableListener changes the certificate for new connections without
// stopping the panel, its control listener or any proxy services. A nil config
// preserves HTTP, including when rolling back a first certificate install.
type ReloadableListener struct {
	net.Listener
	config atomic.Pointer[tls.Config]
}

func NewReloadableListener(listener net.Listener, config *tls.Config) *ReloadableListener {
	l := &ReloadableListener{Listener: listener}
	l.SetTLS(config)
	return l
}

func (l *ReloadableListener) SetTLS(config *tls.Config) {
	if config != nil {
		config = config.Clone()
	}
	l.config.Store(config)
}

func (l *ReloadableListener) TLSConfig() *tls.Config {
	if config := l.config.Load(); config != nil {
		return config.Clone()
	}
	return nil
}

func (l *ReloadableListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if config := l.config.Load(); config != nil {
		return tls.Server(NewAutoHttpsConn(conn), config), nil
	}
	return conn, nil
}
