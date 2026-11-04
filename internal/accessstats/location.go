package accessstats

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

var errLocationDatabaseChanged = errors.New("MMDB changed while loading")

type Location struct {
	Country     string  `json:"country"`
	Subdivision string  `json:"subdivision"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// Locator serializes close/swap against lookups. Published MMDB files must
// always be replaced by rename, never truncated under an active memory map.
type Locator struct {
	mu      sync.RWMutex
	db      *maxminddb.Reader
	Version string
}

func (l *Locator) Open(path, version string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("MMDB must be a regular file")
	}
	validation, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	err = checkLocationFile(path, info)
	if err == nil {
		err = validation.Verify()
	}
	// Full verification touches the entire mapping. Close it before opening
	// the query reader so its resident pages follow actual lookup demand.
	if err = errors.Join(err, validation.Close()); err != nil {
		return err
	}
	db, err := reopenLocationDatabase(path, info)
	if err != nil {
		return err
	}
	l.mu.Lock()
	old := l.db
	l.db, l.Version = db, version
	if old != nil {
		_ = old.Close()
	}
	l.mu.Unlock()
	return nil
}

func checkLocationFile(path string, verified os.FileInfo) error {
	current, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(verified, current) || current.Size() != verified.Size() || !current.ModTime().Equal(verified.ModTime()) {
		return errLocationDatabaseChanged
	}
	return nil
}

func reopenLocationDatabase(path string, verified os.FileInfo) (*maxminddb.Reader, error) {
	if err := checkLocationFile(path, verified); err != nil {
		return nil, err
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	if err = checkLocationFile(path, verified); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return db, nil
}

func (l *Locator) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.db != nil {
		_ = l.db.Close()
		l.db = nil
	}
}

func (l *Locator) Lookup(value string) Location {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return Location{}
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return Location{}
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.db == nil {
		return Location{}
	}
	var data struct {
		Country struct {
			Code string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		Subdivisions []struct {
			Code  string            `maxminddb:"iso_code"`
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"subdivisions"`
		Location struct {
			Latitude  float64 `maxminddb:"latitude"`
			Longitude float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
	}
	if l.db.Lookup(ip).Decode(&data) != nil {
		return Location{}
	}
	location := Location{Country: strings.ToUpper(data.Country.Code), Latitude: data.Location.Latitude, Longitude: data.Location.Longitude}
	if len(data.Subdivisions) > 0 {
		sub := data.Subdivisions[0]
		location.Subdivision = sub.Names["en"]
		if sub.Code != "" {
			location.Subdivision = location.Country + "-" + sub.Code
		}
	}
	return location
}
