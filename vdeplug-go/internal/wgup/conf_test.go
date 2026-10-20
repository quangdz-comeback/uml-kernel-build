package wgup

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// confText renders a wg-quick .conf from generated keys — no real key
// material ever appears in the tree.
func confText(t *testing.T, withMTU bool) (string, []byte, []byte) {
	t.Helper()
	priv, pub, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(k []byte) string { return base64.StdEncoding.EncodeToString(k) }
	mtu := ""
	if withMTU {
		mtu = "MTU = 1380\n"
	}
	text := "[Interface]\n" +
		"PrivateKey = " + b64(priv) + "\n" +
		"Address = 2602:f83b:1886:dff6:31ec:e045:3c64:34f7/128\n" +
		"DNS = 2001:4860:4860::8888\n" +
		mtu +
		"\n[Peer]\n" +
		"PublicKey = " + b64(pub) + "\n" +
		"AllowedIPs =  ::/1, 8000::/1\n" +
		"Endpoint = tw-tpe-ap-1.example:38047\n" +
		"PersistentKeepalive = 25\n"
	return text, priv, pub
}

func TestParseConf(t *testing.T) {
	text, priv, pub := confText(t, true)
	c, err := Parse([]byte(text), "/tmp/v6_test.conf")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(c.PrivateKey) != string(priv) {
		t.Fatal("private key lost in parsing")
	}
	if string(c.PeerKey) != string(pub) {
		t.Fatal("peer key lost in parsing")
	}
	if len(c.Addresses) != 1 || c.Addresses[0].String() != "2602:f83b:1886:dff6:31ec:e045:3c64:34f7/128" {
		t.Fatalf("addresses: %v", c.Addresses)
	}
	if len(c.AllowedIPs) != 2 {
		t.Fatalf("allowedIPs: %v", c.AllowedIPs)
	}
	if c.Endpoint != "tw-tpe-ap-1.example:38047" {
		t.Fatalf("endpoint %q", c.Endpoint)
	}
	if c.Keepalive != 25 {
		t.Fatalf("keepalive %d", c.Keepalive)
	}
	if c.MTU != 1380 {
		t.Fatalf("mtu %d", c.MTU)
	}
	if len(c.DNS) != 1 || c.DNS[0].String() != "2001:4860:4860::8888" {
		t.Fatalf("dns: %v", c.DNS)
	}
}

func TestParseRejectsIncompleteConf(t *testing.T) {
	if _, err := Parse([]byte("[Interface]\nAddress = fd00::1/64\n"), "x.conf"); err == nil {
		t.Fatal("conf without keys parsed")
	}
	priv, pub, _ := GenerateKeys()
	b64 := base64.StdEncoding.EncodeToString
	noPeer := "[Interface]\nPrivateKey = " + b64(priv) + "\n[Peer]\nEndpoint = h:1\nAllowedIPs = ::/0\n"
	if _, err := Parse([]byte(noPeer), "x.conf"); err == nil {
		t.Fatal("conf without peer key parsed")
	}
	noEndpoint := "[Interface]\nPrivateKey = " + b64(priv) + "\n[Peer]\nPublicKey = " + b64(pub) + "\nAllowedIPs = ::/0\n"
	if _, err := Parse([]byte(noEndpoint), "x.conf"); err == nil {
		t.Fatal("conf without endpoint parsed")
	}
}

func TestResolvePathDiscoveryAndOverride(t *testing.T) {
	dir := t.TempDir()
	wgDir := filepath.Join(dir, ".config", "wireguard")
	if err := os.MkdirAll(wgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"zeta.conf", "alpha.conf"} {
		if err := os.WriteFile(filepath.Join(wgDir, name), []byte("[Interface]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)

	got, err := ResolvePath("")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	if filepath.Base(got) != "alpha.conf" {
		t.Fatalf("discovery picked %q, want the first *.conf sorted by name", got)
	}

	override := filepath.Join(dir, "custom.conf")
	if err := os.WriteFile(override, []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = ResolvePath(override)
	if err != nil || got != override {
		t.Fatalf("override: got %q err %v", got, err)
	}

	if _, err := ResolvePath(filepath.Join(dir, "missing.conf")); err == nil {
		t.Fatal("missing override accepted")
	}

	empty := t.TempDir()
	t.Chdir(empty)
	if _, err := ResolvePath(""); err == nil {
		t.Fatal("discovery succeeded without any conf dir")
	}
}
