package service

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

var analysisResourceMu sync.Mutex

func analysisCityPath() string {
	custom := filepath.Join(assetDir(), "access-city.mmdb")
	if _, err := os.Stat(custom); err == nil {
		return custom
	}
	return filepath.Join(assetDir(), "dbip-city.mmdb")
}

func (w *analysisWorker) refreshLocation() {
	analysisResourceMu.Lock()
	defer analysisResourceMu.Unlock()
	path := analysisCityPath()
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	version := fmt.Sprintf("%s:%d:%d", filepath.Base(path), info.Size(), info.ModTime().UnixNano())
	if version == w.resourceVersion {
		return
	}
	if err = w.locator.Open(path, version); err != nil {
		logger.Warningf("Access analysis MMDB: %v", err)
		return
	}
	w.resourceVersion = version
}

// ImportAccessCityDatabase validates a bounded upload before atomic publication.
// The default download remains separate and cannot overwrite a custom import.
func ImportAccessCityDatabase(input io.Reader) error {
	analysisResourceMu.Lock()
	defer analysisResourceMu.Unlock()
	return publishCityDatabase(input, filepath.Join(assetDir(), "access-city.mmdb"))
}

func publishCityDatabase(input io.Reader, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".access-city-*.mmdb")
	if err != nil {
		return err
	}
	name := file.Name()
	defer func() { _ = os.Remove(name) }()
	const limit int64 = 512 << 20
	n, err := io.Copy(file, io.LimitReader(input, limit+1))
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if n > limit {
		return fmt.Errorf("MMDB exceeds size limit")
	}
	db, err := maxminddb.Open(name)
	if err != nil {
		return err
	}
	err = db.Verify()
	databaseType := db.Metadata.DatabaseType
	_ = db.Close()
	if err != nil {
		return err
	}
	if databaseType != "GeoLite2-City" && databaseType != "GeoIP2-City" && databaseType != "DBIP-City-Lite" && databaseType != "DBIP-City" {
		return fmt.Errorf("City MMDB required, got %q", databaseType)
	}
	return os.Rename(name, destination)
}

func runAnalysisDownloads(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		for {
			role, err := (&SettingService{}).GetPanelRole()
			if err == nil && role == PanelRoleMaster {
				downloadDefaultCity(ctx, time.Now().UTC())
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}

func downloadDefaultCity(ctx context.Context, now time.Time) {
	if _, err := os.Stat(filepath.Join(assetDir(), "access-city.mmdb")); err == nil {
		return
	}
	path := filepath.Join(assetDir(), "dbip-city.mmdb")
	if info, err := os.Stat(path); err == nil && info.ModTime().UTC().Format("2006-01") == now.Format("2006-01") {
		return
	}
	requestCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	url := "https://download.db-ip.com/free/dbip-city-lite-" + now.Format("2006-01") + ".mmdb.gz"
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "3x-ui/"+config.GetBaseVersion())
	req.Header.Set("Referer", "https://db-ip.com/db/download/ip-to-city-lite")
	client := &http.Client{Timeout: 3 * time.Minute}
	response, err := client.Do(req)
	if err != nil {
		logger.Warningf("Access analysis DB-IP download: %v", err)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		logger.Warningf("Access analysis DB-IP download: HTTP %d", response.StatusCode)
		return
	}
	reader, err := gzip.NewReader(io.LimitReader(response.Body, 128<<20))
	if err != nil {
		logger.Warningf("Access analysis DB-IP gzip: %v", err)
		return
	}
	defer reader.Close()
	analysisResourceMu.Lock()
	defer analysisResourceMu.Unlock()
	if _, statErr := os.Stat(filepath.Join(assetDir(), "access-city.mmdb")); statErr == nil {
		return
	}
	if err = publishCityDatabase(reader, path); err != nil {
		logger.Warningf("Access analysis DB-IP database: %v", err)
	}
}
