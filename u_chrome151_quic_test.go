package tls

import (
	"context"
	"crypto/ecdh"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// TestHelloChrome151QUICClientHello performs a QUIC handshake with the
// HelloChrome_151_QUIC profile against an in-memory server, intercepts the raw
// ClientHello, and verifies that its composition matches the Chrome 151 QUIC
// reference (temp/research/chrome151-quic-ch-spec.md).
func TestHelloChrome151QUICClientHello(t *testing.T) {
	// The Auto target for the QUIC transport path must resolve to this profile.
	if HelloChrome_Auto_QUIC.Str() != HelloChrome_151_QUIC.Str() {
		t.Fatalf("HelloChrome_Auto_QUIC = %q, want %q", HelloChrome_Auto_QUIC.Str(), HelloChrome_151_QUIC.Str())
	}

	clientConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
	clientConfig.TLSConfig.MinVersion = VersionTLS13
	clientConfig.TLSConfig.ServerName = "www.google.com"
	clientConfig.TLSConfig.NextProtos = []string{"h3"}

	serverConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
	serverConfig.TLSConfig.MinVersion = VersionTLS13
	serverConfig.TLSConfig.NextProtos = []string{"h3"}

	cli := &testQUICConn{t: t, conn: QUICClientWithID(clientConfig, HelloChrome_151_QUIC)}
	t.Cleanup(func() { cli.conn.Close() })
	cli.conn.SetTransportParameters(nil)

	srv := newTestQUICServer(t, serverConfig)
	srv.conn.SetTransportParameters(nil)

	var clientHello []byte
	onEvent := func(e QUICEvent, src, dst *testQUICConn) bool {
		if e.Kind == QUICWriteData && e.Level == QUICEncryptionLevelInitial && src == cli {
			clientHello = append(clientHello, e.Data...)
		}
		return false
	}
	if err := runTestQUICConnection(context.Background(), cli, srv, onEvent); err != nil {
		t.Fatalf("QUIC handshake failed: %v", err)
	}
	if len(clientHello) == 0 {
		t.Fatal("no ClientHello captured from the QUIC handshake")
	}

	ch := parseClientHelloForTest(t, clientHello)
	assertChrome151QUICClientHello(t, ch)
}

// parsedClientHello is a minimal structural view of a ClientHello, tolerant of
// duplicate extensions (unlike clientHelloMsg.unmarshal, which rejects them).
type parsedClientHello struct {
	legacyVersion uint16
	sessionIDLen  int
	cipherSuites  []uint16
	extensions    []parsedExtension
}

type parsedExtension struct {
	typ  uint16
	data []byte
}

func parseClientHelloForTest(t *testing.T, raw []byte) *parsedClientHello {
	t.Helper()
	s := cryptobyte.String(raw)

	var msgType uint8
	var msgLen uint32
	if !s.ReadUint8(&msgType) || msgType != typeClientHello ||
		!s.ReadUint24(&msgLen) || int(msgLen) != len(s) {
		t.Fatalf("bad ClientHello framing: type=%d len=%d have=%d", msgType, msgLen, len(s))
	}

	ch := &parsedClientHello{}
	if !s.ReadUint16(&ch.legacyVersion) {
		t.Fatal("short legacy_version")
	}
	var random []byte
	if !s.ReadBytes(&random, 32) {
		t.Fatal("short random")
	}
	var sessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		t.Fatal("short session_id")
	}
	ch.sessionIDLen = len(sessionID)

	var suites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&suites) {
		t.Fatal("short cipher_suites")
	}
	for !suites.Empty() {
		var cs uint16
		if !suites.ReadUint16(&cs) {
			t.Fatal("short cipher suite")
		}
		ch.cipherSuites = append(ch.cipherSuites, cs)
	}

	var comp cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&comp) {
		t.Fatal("short compression_methods")
	}

	if s.Empty() {
		return ch
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) {
		t.Fatal("short extensions block")
	}
	for !exts.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&data) {
			t.Fatal("short extension entry")
		}
		ch.extensions = append(ch.extensions, parsedExtension{typ: typ, data: append([]byte{}, data...)})
	}
	return ch
}

func (ch *parsedClientHello) extData(typ uint16) ([]byte, bool) {
	for _, e := range ch.extensions {
		if e.typ == typ {
			return e.data, true
		}
	}
	return nil, false
}

func (ch *parsedClientHello) hasExtension(typ uint16) bool {
	for _, e := range ch.extensions {
		if e.typ == typ {
			return true
		}
	}
	return false
}

func assertChrome151QUICClientHello(t *testing.T, ch *parsedClientHello) {
	t.Helper()

	// --- 1. Basic fields ---------------------------------------------------
	if ch.legacyVersion != VersionTLS12 {
		t.Errorf("legacy_version = 0x%04x, want 0x0303", ch.legacyVersion)
	}
	if ch.sessionIDLen != 0 {
		t.Errorf("session_id length = %d, want 0", ch.sessionIDLen)
	}

	// --- 2. Cipher suites: exactly 3, fixed order, no GREASE -----------------
	wantSuites := []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256}
	if len(ch.cipherSuites) != len(wantSuites) {
		t.Errorf("cipher suites = %#v (len %d), want exactly %d suites", ch.cipherSuites, len(ch.cipherSuites), len(wantSuites))
	} else {
		for i := range wantSuites {
			if ch.cipherSuites[i] != wantSuites[i] {
				t.Errorf("cipher suite[%d] = 0x%04x, want 0x%04x", i, ch.cipherSuites[i], wantSuites[i])
			}
		}
	}
	for _, cs := range ch.cipherSuites {
		if isGREASEUint16(cs) {
			t.Errorf("GREASE cipher suite 0x%04x present, want none", cs)
		}
	}

	// --- 3. Extension set ----------------------------------------------------
	for _, typ := range []uint16{
		ExtensionServerName,                 // 0
		ExtensionSupportedCurves,            // 10
		ExtensionSignatureAlgorithms,        // 13
		ExtensionALPN,                       // 16
		ExtensionCompressCertificate,        // 27
		ExtensionSupportedVersions,          // 43
		ExtensionPSKModes,                   // 45
		ExtensionKeyShare,                   // 51
		utlsExtensionApplicationSettingsNew, // 17613
		extensionEncryptedClientHello,       // 65037
	} {
		if !ch.hasExtension(typ) {
			t.Errorf("missing required extension 0x%04x", typ)
		}
	}

	// Legacy + GREASE extensions that must be absent.
	for _, typ := range []uint16{
		ExtensionRenegotiationInfo,    // 65281
		ExtensionExtendedMasterSecret, // 23
		ExtensionSupportedPoints,      // 11 ec_point_formats
		ExtensionSessionTicket,        // 35
		ExtensionStatusRequest,        // 5
		ExtensionSCT,                  // 18
	} {
		if ch.hasExtension(typ) {
			t.Errorf("legacy extension 0x%04x present, want absent", typ)
		}
	}
	for _, e := range ch.extensions {
		if isGREASEUint16(e.typ) {
			t.Errorf("GREASE extension 0x%04x present, want none", e.typ)
		}
	}

	// quic_transport_parameters (57) is appended by quic-go, not by the preset.
	if !ch.hasExtension(ExtensionQUICTransportParameters) {
		t.Errorf("missing quic_transport_parameters (57)")
	}

	// --- 4. supported_versions: only TLS 1.3 ---------------------------------
	if sv, ok := ch.extData(ExtensionSupportedVersions); ok {
		assertUint8List(t, "supported_versions", sv, []uint16{VersionTLS13})
	} else {
		t.Errorf("supported_versions extension missing")
	}

	// --- 5. supported_groups: fixed order, no GREASE -------------------------
	if sg, ok := ch.extData(ExtensionSupportedCurves); ok {
		assertUint16List(t, "supported_groups", sg, []uint16{
			uint16(X25519MLKEM768), // 0x11ec
			uint16(X25519),         // 0x001d
			uint16(CurveP256),      // 0x0017
			uint16(CurveP384),      // 0x0018
		})
	} else {
		t.Errorf("supported_groups extension missing")
	}

	// --- 6. signature_algorithms: 9, fixed order, rsa_pkcs1_sha1 last --------
	if sa, ok := ch.extData(ExtensionSignatureAlgorithms); ok {
		assertUint16List(t, "signature_algorithms", sa, []uint16{
			uint16(ECDSAWithP256AndSHA256), // 0x0403
			uint16(PSSWithSHA256),          // 0x0804
			uint16(PKCS1WithSHA256),        // 0x0401
			uint16(ECDSAWithP384AndSHA384), // 0x0503
			uint16(PSSWithSHA384),          // 0x0805
			uint16(PKCS1WithSHA384),        // 0x0501
			uint16(PSSWithSHA512),          // 0x0806
			uint16(PKCS1WithSHA512),        // 0x0601
			uint16(PKCS1WithSHA1),          // 0x0201
		})
	} else {
		t.Errorf("signature_algorithms extension missing")
	}

	// --- 7. key_share: X25519MLKEM768 (1216B) then x25519 (32B) --------------
	if ks, ok := ch.extData(ExtensionKeyShare); ok {
		assertKeyShare(t, ks)
	} else {
		t.Errorf("key_share extension missing")
	}

	// --- 8. psk_key_exchange_modes: psk_dhe_ke only --------------------------
	if pm, ok := ch.extData(ExtensionPSKModes); ok {
		s := cryptobyte.String(pm)
		var modes cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&modes) {
			t.Fatalf("short psk_key_exchange_modes")
		}
		if len(modes) != 1 {
			t.Fatalf("psk_key_exchange_modes has %d modes, want 1", len(modes))
		}
		var mode uint8
		modes.ReadUint8(&mode)
		if mode != PskModeDHE {
			t.Errorf("psk_key_exchange_mode = %d, want psk_dhe_ke (%d)", mode, PskModeDHE)
		}
	} else {
		t.Errorf("psk_key_exchange_modes extension missing")
	}

	// --- 9. ALPN = h3 --------------------------------------------------------
	if alpn, ok := ch.extData(ExtensionALPN); ok {
		assertProtocolList(t, "ALPN", alpn, []string{"h3"})
	} else {
		t.Errorf("ALPN extension missing")
	}

	// --- 10. ALPS (application_settings, 17613) = h3 -------------------------
	if alps, ok := ch.extData(utlsExtensionApplicationSettingsNew); ok {
		s := cryptobyte.String(alps)
		var protoList cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&protoList) {
			t.Fatalf("short ALPS extension data")
		}
		var protos []string
		for !protoList.Empty() {
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) {
				t.Fatalf("short ALPS protocol")
			}
			protos = append(protos, string(proto))
		}
		if len(protos) != 1 || protos[0] != "h3" {
			t.Errorf("ALPS protocols = %v, want [h3]", protos)
		}
	} else {
		t.Errorf("ALPS (application_settings) extension missing")
	}

	// --- 11. compress_certificate = brotli only ------------------------------
	if cc, ok := ch.extData(ExtensionCompressCertificate); ok {
		assertUint8List(t, "compress_certificate", cc, []uint16{uint16(CertCompressionBrotli)})
	} else {
		t.Errorf("compress_certificate extension missing")
	}

	// --- 12. GREASE ECH structure (RFC 9849) ---------------------------------
	if ech, ok := ch.extData(extensionEncryptedClientHello); ok {
		assertGreaseECH(t, ech)
	} else {
		t.Errorf("encrypted_client_hello (ECH) extension missing")
	}
}

// assertUint16List parses a uint16-length-prefixed list and compares it in order.
func assertUint16List(t *testing.T, name string, data []byte, want []uint16) {
	t.Helper()
	s := cryptobyte.String(data)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) {
		t.Fatalf("short %s list", name)
	}
	var got []uint16
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			t.Fatalf("short %s entry", name)
		}
		got = append(got, v)
	}
	if len(got) != len(want) {
		t.Errorf("%s = %#v (len %d), want %#v (len %d)", name, got, len(got), want, len(want))
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = 0x%04x, want 0x%04x", name, i, got[i], want[i])
		}
	}
}

// assertUint8List parses a uint8-length-prefixed list (supported_versions,
// compress_certificate) and compares it in order.
func assertUint8List(t *testing.T, name string, data []byte, want []uint16) {
	t.Helper()
	s := cryptobyte.String(data)
	var list cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&list) {
		t.Fatalf("short %s list", name)
	}
	var got []uint16
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			t.Fatalf("short %s entry", name)
		}
		got = append(got, v)
	}
	if len(got) != len(want) {
		t.Errorf("%s = %#v (len %d), want %#v (len %d)", name, got, len(got), want, len(want))
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = 0x%04x, want 0x%04x", name, i, got[i], want[i])
		}
	}
}

func assertKeyShare(t *testing.T, data []byte) {
	t.Helper()
	s := cryptobyte.String(data)
	var shares cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&shares) {
		t.Fatalf("short key_share")
	}
	type share struct {
		group uint16
		n     int
	}
	var got []share
	for !shares.Empty() {
		var group uint16
		var keyExchange cryptobyte.String
		if !shares.ReadUint16(&group) || !shares.ReadUint16LengthPrefixed(&keyExchange) {
			t.Fatalf("short key_share entry")
		}
		got = append(got, share{group: group, n: len(keyExchange)})
	}

	want := []share{
		{group: uint16(X25519MLKEM768), n: 1216}, // ML-KEM-768 (1184) + X25519 (32)
		{group: uint16(X25519), n: 32},
	}
	if len(got) != len(want) {
		t.Fatalf("key_share has %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].group != want[i].group {
			t.Errorf("key_share[%d].group = 0x%04x, want 0x%04x", i, got[i].group, want[i].group)
		}
		if got[i].n != want[i].n {
			t.Errorf("key_share[%d].key_exchange length = %d, want %d", i, got[i].n, want[i].n)
		}
	}
}

func assertProtocolList(t *testing.T, name string, data []byte, want []string) {
	t.Helper()
	s := cryptobyte.String(data)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) {
		t.Fatalf("short %s list", name)
	}
	var got []string
	for !list.Empty() {
		var p cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&p) {
			t.Fatalf("short %s protocol", name)
		}
		got = append(got, string(p))
	}
	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v", name, got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %q, want %q", name, i, got[i], want[i])
		}
	}
}

// assertGreaseECH verifies the GREASE ECH structure per RFC 9849 and the
// chrome151-quic-ch-spec.md reference: outer type, HKDF-SHA256/AES-128-GCM,
// 32-byte X25519 enc, and payload length from {144,176,208,240}.
func assertGreaseECH(t *testing.T, data []byte) {
	t.Helper()
	s := cryptobyte.String(data)

	var chType uint8
	if !s.ReadUint8(&chType) || chType != 0 {
		t.Fatalf("ECH client_hello_type = %d, want 0 (outer)", chType)
	}
	var kdfID, aeadID uint16
	if !s.ReadUint16(&kdfID) || !s.ReadUint16(&aeadID) {
		t.Fatalf("short ECH cipher suite")
	}
	if kdfID != 0x0001 {
		t.Errorf("ECH kdf_id = 0x%04x, want 0x0001 (HKDF-SHA256)", kdfID)
	}
	if aeadID != 0x0001 {
		t.Errorf("ECH aead_id = 0x%04x, want 0x0001 (AES-128-GCM)", aeadID)
	}

	var configID uint8
	if !s.ReadUint8(&configID) {
		t.Fatalf("short ECH config_id")
	}

	var enc cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&enc) {
		t.Fatalf("short ECH enc")
	}
	if len(enc) != 32 {
		t.Fatalf("ECH enc length = %d, want 32", len(enc))
	}
	// enc must be a valid X25519 public key (a valid curve point).
	if _, err := ecdh.X25519().NewPublicKey(append([]byte{}, enc...)); err != nil {
		t.Errorf("ECH enc is not a valid X25519 point: %v", err)
	}

	var payload cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&payload) {
		t.Fatalf("short ECH payload")
	}
	switch len(payload) {
	case 144, 176, 208, 240:
	default:
		t.Errorf("ECH payload length = %d, want one of {144,176,208,240}", len(payload))
	}
	if !s.Empty() {
		t.Errorf("ECH has %d trailing bytes after payload", len(s))
	}
}
