// Package accessstats enriches archived connection events. It never changes
// collection, routing decisions, or the original archive.
package accessstats

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

const CatalogVersion = "2"

type Application struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Color   string   `json:"color"`
	Domains []string `json:"-"`
}

// Built-in metadata and explicit domains preserve existing IDs when geosite is
// absent. The remaining service catalog is discovered from the local database.
var Applications = []Application{
	{"youtube", "YouTube", "#e62117", []string{"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com"}},
	{"github", "GitHub", "#59636e", []string{"github.com", "githubusercontent.com", "githubassets.com"}},
	{"telegram", "Telegram", "#229ed9", []string{"telegram.org", "t.me", "telegram.me"}},
	{"netflix", "Netflix", "#e50914", []string{"netflix.com", "nflxvideo.net", "nflximg.net"}},
	{"spotify", "Spotify", "#1db954", []string{"spotify.com", "scdn.co", "spotifycdn.com"}},
	{"discord", "Discord", "#5865f2", []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net"}},
	{"whatsapp", "WhatsApp", "#25d366", []string{"whatsapp.com", "whatsapp.net"}},
	{"instagram", "Instagram", "#c13584", []string{"instagram.com", "cdninstagram.com"}},
	{"facebook", "Facebook", "#1877f2", []string{"facebook.com", "fb.com", "fbcdn.net"}},
	{"twitter", "X", "#657786", []string{"twitter.com", "x.com", "twimg.com", "t.co"}},
	{"tiktok", "TikTok", "#25a4a8", []string{"tiktok.com", "tiktokcdn.com", "tiktokv.com"}},
	{"reddit", "Reddit", "#ff4500", []string{"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"}},
	{"openai", "OpenAI", "#10a37f", []string{"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"}},
	{"claude", "Claude", "#c96442", []string{"claude.ai", "anthropic.com"}},
	{"steam", "Steam", "#1b5280", []string{"steampowered.com", "steamcommunity.com", "steamstatic.com"}},
	{"bilibili", "Bilibili", "#00a1d6", []string{"bilibili.com", "bilivideo.com", "biliimg.com", "hdslb.com"}},
	{"douyin", "Douyin", "#252535", []string{"douyin.com", "douyincdn.com"}},
	{"twitch", "Twitch", "#9146ff", []string{"twitch.tv", "ttvnw.net", "jtvnw.net"}},
	{"zoom", "Zoom", "#2d8cff", []string{"zoom.us", "zoom.com"}},
	{"dropbox", "Dropbox", "#0061ff", []string{"dropbox.com", "dropboxapi.com", "dropboxusercontent.com"}},
	{"google", "Google", "#4285f4", []string{"google.com", "googleapis.com"}},
	{"microsoft", "Microsoft", "#0078d4", []string{"microsoft.com", "live.com", "office.com", "office365.com"}},
	{"apple", "Apple", "#7d7d7d", []string{"apple.com", "icloud.com"}},
}

func Host(value string) string {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if addr, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return addr.Unmap().String()
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || len(ascii) > 253 || strings.ContainsAny(ascii, " /:@") {
		return ""
	}
	return ascii
}

func Key(values ...any) string {
	data, _ := json.Marshal(values)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func Domain(value string) string {
	host := Host(value)
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	return host
}
