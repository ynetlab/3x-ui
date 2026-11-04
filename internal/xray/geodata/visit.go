package geodata

import (
	"context"
	"errors"
	"io"
	"os"
)

// WalkSiteRules reads selected categories through one file handle and reuses a
// single record buffer. Unlike Entries it does not re-scan categories for pages
// or retain a hot copy. The visitor receives only domain/full rules; attributes
// allow consumers to exclude advertising without changing routing semantics.
// A changed/truncated database is an error, never a partial successful snapshot.
func (s *Store) WalkSiteRules(ctx context.Context, name string, accept func(string) bool, visit func(string, GeoEntry, []string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := s.resolve(name)
	if err != nil {
		return err
	}
	idx, err := s.index(name)
	if err != nil {
		return err
	}
	if idx.kind != KindSite {
		return ErrUnrecognized
	}
	s.scan.Lock()
	defer s.scan.Unlock()
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !sameDatabase(before, opened) {
		return errors.New("geosite changed during application scan")
	}
	var buffer []byte
	for _, category := range idx.categories {
		if !accept(category.Code) {
			continue
		}
		for _, span := range idx.spans[category.Code] {
			if err := ctx.Err(); err != nil {
				return err
			}
			if span.length <= 0 || span.length > MaxFileSize {
				return ErrUnrecognized
			}
			if int64(cap(buffer)) < span.length {
				buffer = make([]byte, span.length)
			}
			record := buffer[:span.length]
			if _, err := file.ReadAt(record, span.offset); err != nil {
				return err
			}
			code, err := walkEntry(record, func(payload []byte) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				kind := domainKind(payload)
				if kind != "domain" && kind != "full" {
					return nil
				}
				value, attributes, err := domainValue(payload)
				if err != nil {
					return err
				}
				return visit(category.Code, GeoEntry{Kind: kind, Value: string(value)}, attributes)
			})
			if err != nil {
				return err
			}
			if code != category.Code {
				return ErrUnrecognized
			}
		}
	}
	after, err := s.resolve(name)
	if err != nil {
		return err
	}
	if !sameDatabase(before, after) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func sameDatabase(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
