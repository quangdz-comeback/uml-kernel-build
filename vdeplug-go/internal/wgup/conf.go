// Package wgup attaches a userspace WireGuard tunnel (wireguard-go) to the
// running netstack as an additional uplink. Two modes, chosen by how the
// instance runs:
//
//   - Standalone (no switch): the tunnel's Address= is the guest's own
//     address — netstack never owns it and does not NAT it; matching
//     traffic is forwarded statelessly between guest and tunnel.
//   - Switch (hub+peers): guests keep the slirp NAT (10.0.2.0/24, DHCP),
//     but NAT flows egress through the tunnel with the tunnel address as
//     the source, replacing the host's own address.
//
// Configs are standard wg-quick(8) .conf files. The tunnel config contains
// private keys — nothing in this package ever logs one.
package wgup

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Conf is the parsed subset of a wg-quick .conf that vdeplug uses.
type Conf struct {
	Path string

	PrivateKey   []byte      // 32 bytes
	PresharedKey []byte      // 32 bytes, optional
	Addresses    []net.IPNet // Address= entries (with prefixes)
	DNS          []net.IP    // informational: guest DNS stays proxied
	PeerKey      []byte      // 32 bytes
	AllowedIPs   []net.IPNet // routes into the tunnel
	Endpoint     string      // host:port
	Keepalive    uint16      // seconds, 0 = off
	MTU          int         // 0 = wireguard default 1420
}

// Parse reads a wg-quick .conf from memory. Keys are base64 on the wire
// format and are decoded, never logged.
func Parse(data []byte, path string) (*Conf, error) {
	c := &Conf{Path: path}
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[]")
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("%s:%d: not key=value", filepath.Base(path), lineNo)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		var err error
		switch section {
		case "Interface":
			switch key {
			case "privatekey":
				c.PrivateKey, err = decodeKey(value, path, lineNo)
			case "address":
				c.Addresses, err = parseCIDRs(value, path, lineNo)
			case "dns":
				for _, d := range strings.Split(value, ",") {
					if ip := net.ParseIP(strings.TrimSpace(d)); ip != nil {
						c.DNS = append(c.DNS, ip)
					}
				}
			case "mtu":
				c.MTU, err = strconv.Atoi(value)
			}
		case "Peer":
			switch key {
			case "publickey":
				c.PeerKey, err = decodeKey(value, path, lineNo)
			case "presharedkey":
				c.PresharedKey, err = decodeKey(value, path, lineNo)
			case "allowedips":
				c.AllowedIPs, err = parseCIDRs(value, path, lineNo)
			case "endpoint":
				if _, _, splitErr := net.SplitHostPort(value); splitErr != nil {
					return nil, fmt.Errorf("%s:%d: endpoint %q: %w", filepath.Base(path), lineNo, value, splitErr)
				}
				c.Endpoint = value
			case "persistentkeepalive":
				var ka int
				if ka, err = strconv.Atoi(value); err == nil && (ka < 0 || ka > 65535) {
					err = fmt.Errorf("keepalive %d out of range", ka)
				}
				c.Keepalive = uint16(ka)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %s: %w", filepath.Base(path), lineNo, key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(c.PrivateKey) == 0 {
		return nil, fmt.Errorf("%s: no PrivateKey", filepath.Base(path))
	}
	if len(c.PeerKey) == 0 {
		return nil, fmt.Errorf("%s: no Peer PublicKey", filepath.Base(path))
	}
	if len(c.AllowedIPs) == 0 {
		return nil, fmt.Errorf("%s: no AllowedIPs", filepath.Base(path))
	}
	if c.Endpoint == "" {
		return nil, fmt.Errorf("%s: no Endpoint", filepath.Base(path))
	}
	return c, nil
}

// Load reads and parses the config file at path.
func Load(path string) (*Conf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

// ResolvePath names the tunnel config: the YAML override wins; otherwise
// the first *.conf (sorted by name) inside $PWD/.config/wireguard.
func ResolvePath(override string) (string, error) {
	if override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", fmt.Errorf("wireguard_conf_path %q: %w", override, err)
		}
		return override, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("wireguard: %w", err)
	}
	dir := filepath.Join(wd, ".config", "wireguard")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("wireguard: no config found: %w (set wireguard_conf_path in config.yaml)", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("wireguard: no *.conf in %s (set wireguard_conf_path in config.yaml)", dir)
	}
	sort.Strings(names)
	return filepath.Join(dir, names[0]), nil
}

// GenerateKeys mints a fresh Curve25519 keypair for tests: private and
// public, 32 bytes each.
func GenerateKeys() (priv, pub []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

// base64Key decodes a wg-quick base64 key into its 32 raw bytes.
func decodeKey(value, path string, lineNo int) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("%s:%d: key must be 32 base64-encoded bytes", filepath.Base(path), lineNo)
	}
	return raw, nil
}

// parseCIDRs splits a comma-separated CIDR list (wg-quick style).
func parseCIDRs(value, path string, lineNo int) ([]net.IPNet, error) {
	var out []net.IPNet
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(part)
		if err != nil {
			// Bare address without prefix: host route.
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("%s:%d: %q: not a CIDR", filepath.Base(path), lineNo, part)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		out = append(out, *ipnet)
	}
	return out, nil
}
