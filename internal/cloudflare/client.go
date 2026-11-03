// Package cloudflare implements the small DNS API surface used by node domains.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

const apiURL = "https://api.cloudflare.com/client/v4"
const RequestTimeout = 10 * time.Second
const maxResponseBytes = 2 << 20

var identifier = regexp.MustCompile(`^[a-f0-9]{32}$`)

func ValidID(value string) bool { return identifier.MatchString(value) }

type Record struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Content   string `json:"content"`
	TTL       int    `json:"ttl"`
	Proxied   bool   `json:"proxied"`
	Proxiable bool   `json:"proxiable"`
}

type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Page struct {
	Records                 []Record
	Page, TotalPages, Total int
}

// Error exposes stable codes, never provider text, bodies, URLs or bearer data.
type Error struct {
	Code          string
	Status        int
	ProviderCodes []int
	RetryAfter    int
}

func (e *Error) Error() string { return e.Code }

func IsNotFound(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	if e.Status == 404 {
		return true
	}
	for _, code := range e.ProviderCodes {
		if code == 81044 {
			return true
		}
	}
	return false
}

type Client struct {
	token string
	http  http.Client
}

func New(token string, client *http.Client) *Client {
	if client == nil {
		client = &http.Client{}
	}
	copy := *client
	copy.Timeout = RequestTimeout
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{token: token, http: copy}
}

type envelope struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Code int `json:"code"`
	} `json:"errors"`
	Info struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
		Total      int `json:"total_count"`
	} `json:"result_info"`
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, input any) (envelope, error) {
	var result envelope
	var data []byte
	if input != nil {
		var err error
		data, err = json.Marshal(input)
		if err != nil {
			return result, errors.New("invalid_cloudflare_request")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	u := apiURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(data))
	if err != nil {
		return result, errors.New("invalid_cloudflare_request")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return result, &Error{Code: "cloudflare_unreachable", Status: 504}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(body) > maxResponseBytes {
		return result, &Error{Code: "cloudflare_invalid_response", Status: 502}
	}
	decoded := json.Unmarshal(body, &result) == nil
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !decoded || !result.Success {
		e := &Error{Code: "cloudflare_api_error", Status: 502}
		for _, item := range result.Errors {
			e.ProviderCodes = append(e.ProviderCodes, item.Code)
		}
		switch resp.StatusCode {
		case 401, 403:
			e.Code = "cloudflare_auth_failed"
		case 404:
			e.Code, e.Status = "cloudflare_record_not_found", 404
		case 429:
			e.Code, e.Status = "cloudflare_rate_limited", 429
			if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds > 0 && seconds <= 86400 {
				e.RetryAfter = seconds
			}
		}
		if !decoded {
			e.Code = "cloudflare_invalid_response"
		}
		return result, e
	}
	return result, nil
}

func zonePath(zone string) (string, error) {
	if !ValidID(zone) {
		return "", errors.New("invalid_cloudflare_zone_id")
	}
	return "/zones/" + zone, nil
}

func recordPath(zone, id string) (string, error) {
	p, err := zonePath(zone)
	if err != nil {
		return "", err
	}
	if !ValidID(id) {
		return "", errors.New("invalid_cloudflare_record_id")
	}
	return p + "/dns_records/" + id, nil
}

func (c *Client) Zone(ctx context.Context, zone string) (Zone, error) {
	path, err := zonePath(zone)
	if err != nil {
		return Zone{}, err
	}
	raw, err := c.do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return Zone{}, err
	}
	var value Zone
	if json.Unmarshal(raw.Result, &value) != nil || value.ID != zone || value.Name == "" {
		return Zone{}, &Error{Code: "cloudflare_invalid_response", Status: 502}
	}
	return value, nil
}

func (c *Client) List(ctx context.Context, zone string, query url.Values) (Page, error) {
	path, err := zonePath(zone)
	if err != nil {
		return Page{}, err
	}
	raw, err := c.do(ctx, http.MethodGet, path+"/dns_records", query, nil)
	if err != nil {
		return Page{}, err
	}
	page := Page{Page: raw.Info.Page, TotalPages: raw.Info.TotalPages, Total: raw.Info.Total}
	if json.Unmarshal(raw.Result, &page.Records) != nil || page.Records == nil || len(page.Records) > 100 {
		return Page{}, &Error{Code: "cloudflare_invalid_response", Status: 502}
	}
	for _, r := range page.Records {
		if !ValidID(r.ID) {
			return Page{}, &Error{Code: "cloudflare_invalid_response", Status: 502}
		}
	}
	return page, nil
}

func decodeRecord(raw envelope, id string) (Record, error) {
	var record Record
	if json.Unmarshal(raw.Result, &record) != nil || !ValidID(record.ID) || id != "" && record.ID != id {
		return Record{}, &Error{Code: "cloudflare_invalid_response", Status: 502}
	}
	return record, nil
}

func (c *Client) Get(ctx context.Context, zone, id string) (Record, error) {
	path, err := recordPath(zone, id)
	if err != nil {
		return Record{}, err
	}
	raw, err := c.do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return Record{}, err
	}
	return decodeRecord(raw, id)
}

func (c *Client) Create(ctx context.Context, zone string, input any) (Record, error) {
	path, err := zonePath(zone)
	if err != nil {
		return Record{}, err
	}
	raw, err := c.do(ctx, http.MethodPost, path+"/dns_records", nil, input)
	if err != nil {
		return Record{}, err
	}
	return decodeRecord(raw, "")
}

func (c *Client) Update(ctx context.Context, zone, id string, input any) (Record, error) {
	path, err := recordPath(zone, id)
	if err != nil {
		return Record{}, err
	}
	raw, err := c.do(ctx, http.MethodPatch, path, nil, input)
	if err != nil {
		return Record{}, err
	}
	return decodeRecord(raw, id)
}

func (c *Client) Delete(ctx context.Context, zone, id string) error {
	path, err := recordPath(zone, id)
	if err != nil {
		return err
	}
	raw, err := c.do(ctx, http.MethodDelete, path, nil, nil)
	if err != nil {
		return err
	}
	var result struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw.Result, &result) != nil || result.ID != id {
		return &Error{Code: "cloudflare_invalid_response", Status: 502}
	}
	return nil
}
