package tls

import (
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// TestHelloAndroid15OkHttpClientHello performs a TCP handshake of the
// HelloAndroid_15_OkHttp profile against a local crypto/tls server, captures
// the raw ClientHello on the wire, and verifies its composition against the
// OkHttp/Conscrypt reference (temp/v2_okhttp_profile_audit.md §6.2).
func TestHelloAndroid15OkHttpClientHello(t *testing.T) {
	cert := newTestServerCert(t)

	serverConfig := &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		// The v2 relay serves HTTP/1.1; from [h2, http/1.1] it picks http/1.1.
		NextProtos: []string{"http/1.1"},
	}
	clientConfig := &Config{
		ServerName:         "okhttp.test",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	type serverResult struct {
		clientHello []byte
		err         error
	}
	serverDone := make(chan serverResult, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		defer conn.Close()
		rec := &recordingConn{Conn: conn}
		srv := stdtls.Server(rec, serverConfig)
		if err := srv.Handshake(); err != nil {
			serverDone <- serverResult{err: fmt.Errorf("server handshake: %v", err)}
			return
		}
		// The first recorded flow is everything the client sent before the
		// server's flight, i.e. the full ClientHello record.
		var firstFlow []byte
		if len(rec.flows) > 0 {
			firstFlow = rec.flows[0]
		}
		ch, err := extractClientHelloFromRecord(firstFlow)
		serverDone <- serverResult{clientHello: ch, err: err}
	}()

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	uconn := UClient(rawConn, clientConfig, HelloAndroid_15_OkHttp, false, false, false)
	if err := uconn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	cs := uconn.ConnectionState()
	if cs.Version != VersionTLS13 {
		t.Errorf("negotiated version = 0x%04x, want TLS 1.3 (0x0304)", cs.Version)
	}
	if cs.NegotiatedProtocol != "http/1.1" {
		t.Errorf("negotiated ALPN = %q, want http/1.1", cs.NegotiatedProtocol)
	}
	uconn.Close()

	res := <-serverDone
	if res.err != nil {
		t.Fatalf("server: %v", res.err)
	}
	if len(res.clientHello) == 0 {
		t.Fatal("no ClientHello captured from the handshake")
	}

	ch := parseClientHelloForTest(t, res.clientHello)
	assertHelloAndroid15OkHttpClientHello(t, ch)
}

// extractClientHelloFromRecord pulls the ClientHello handshake message (type
// byte + 3-byte length + body) out of the first TLS record in data. The
// following records (ServerHello etc.) are ignored.
func extractClientHelloFromRecord(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("record too short: %d bytes", len(data))
	}
	if data[0] != byte(recordTypeHandshake) {
		return nil, fmt.Errorf("first record type = %d, want %d (handshake)", data[0], recordTypeHandshake)
	}
	length := int(data[3])<<8 | int(data[4])
	if len(data) < 5+length {
		return nil, fmt.Errorf("record truncated: header says %d bytes, have %d", length, len(data)-5)
	}
	return data[5 : 5+length], nil
}

// newTestServerCert generates a self-signed RSA certificate for the local
// test server.
func newTestServerCert(t *testing.T) stdtls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "okhttp.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"okhttp.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return stdtls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

// assertHelloAndroid15OkHttpClientHello verifies the wire structure of the
// Android 15 OkHttp ClientHello against the OkHttp/Conscrypt reference
// (temp/v2_okhttp_profile_audit.md §6.2).
func assertHelloAndroid15OkHttpClientHello(t *testing.T, ch *parsedClientHello) {
	t.Helper()

	// --- 1. Basic fields ---------------------------------------------------
	if ch.legacyVersion != VersionTLS12 {
		t.Errorf("legacy_version = 0x%04x, want 0x0303 (TLS 1.2)", ch.legacyVersion)
	}
	// TCP (non-QUIC) handshakes carry a random 32-byte session id.
	if ch.sessionIDLen != 32 {
		t.Errorf("session_id length = %d, want 32", ch.sessionIDLen)
	}

	// --- 2. Cipher suites: 19, fixed order, no GREASE ----------------------
	wantSuites := []uint16{
		TLS_AES_128_GCM_SHA256,                        // 0x1301
		TLS_AES_256_GCM_SHA384,                        // 0x1302
		TLS_CHACHA20_POLY1305_SHA256,                  // 0x1303
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       // 0xc02b
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       // 0xc02c
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // 0xcca9
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         // 0xc02f
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         // 0xc030
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   // 0xcca8
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,          // 0xc009
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,          // 0xc00a
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,            // 0xc013
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,            // 0xc014
		TLS_RSA_WITH_AES_128_GCM_SHA256,               // 0x009c
		TLS_RSA_WITH_AES_256_GCM_SHA384,               // 0x009d
		TLS_RSA_WITH_AES_128_CBC_SHA,                  // 0x002f
		TLS_RSA_WITH_AES_256_CBC_SHA,                  // 0x0035
		FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,        // 0x00ff
		TLS_FALLBACK_SCSV,                             // 0x5600
	}
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

	// --- 3. Extension set: all required present ------------------------------
	for _, typ := range []uint16{
		ExtensionServerName,           // 0
		ExtensionExtendedMasterSecret, // 23
		ExtensionRenegotiationInfo,    // 65281
		ExtensionSupportedCurves,      // 10
		ExtensionSupportedPoints,      // 11
		ExtensionStatusRequest,        // 5
		ExtensionSignatureAlgorithms,  // 13
		ExtensionALPN,                 // 16
		ExtensionSupportedVersions,    // 43
		ExtensionKeyShare,             // 51
		ExtensionPSKModes,             // 45
		ExtensionSessionTicket,        // 35
	} {
		if !ch.hasExtension(typ) {
			t.Errorf("missing required extension 0x%04x", typ)
		}
	}

	// --- 4. Extensions that must be absent -----------------------------------
	// OkHttp/Conscrypt (Java SSLEngine) sends no GREASE, ECH, ALPS,
	// compress_certificate, padding, SCT, record_size_limit.
	for _, typ := range []uint16{
		ExtensionCompressCertificate,        // 27 compress_certificate
		ExtensionSCT,                        // 18
		utlsExtensionPadding,                // 21
		fakeRecordSizeLimit,                 // 28 record_size_limit
		utlsExtensionApplicationSettingsNew, // 17613 ALPS
		extensionEncryptedClientHello,       // 65037 ECH
	} {
		if ch.hasExtension(typ) {
			t.Errorf("extension 0x%04x present, want absent", typ)
		}
	}
	for _, e := range ch.extensions {
		if isGREASEUint16(e.typ) {
			t.Errorf("GREASE extension 0x%04x present, want none", e.typ)
		}
	}

	// --- 5. Extension order: fixed Conscrypt order ---------------------------
	wantOrder := []uint16{
		ExtensionServerName,           // 0
		ExtensionExtendedMasterSecret, // 23
		ExtensionRenegotiationInfo,    // 65281
		ExtensionSupportedCurves,      // 10
		ExtensionSupportedPoints,      // 11
		ExtensionStatusRequest,        // 5
		ExtensionSignatureAlgorithms,  // 13
		ExtensionALPN,                 // 16
		ExtensionSupportedVersions,    // 43
		ExtensionKeyShare,             // 51
		ExtensionPSKModes,             // 45
		ExtensionSessionTicket,        // 35
	}
	if len(ch.extensions) != len(wantOrder) {
		t.Errorf("extensions = %v (len %d), want %d extensions", parsedExtTypes(ch.extensions), len(ch.extensions), len(wantOrder))
	} else {
		for i := range wantOrder {
			if ch.extensions[i].typ != wantOrder[i] {
				t.Errorf("extension[%d] = 0x%04x, want 0x%04x; full order %v",
					i, ch.extensions[i].typ, wantOrder[i], parsedExtTypes(ch.extensions))
				break
			}
		}
	}

	// --- 6. supported_versions: [1.3, 1.2, 1.1, 1.0], no GREASE --------------
	if sv, ok := ch.extData(ExtensionSupportedVersions); ok {
		assertUint8List(t, "supported_versions", sv, []uint16{VersionTLS13, VersionTLS12, VersionTLS11, VersionTLS10})
	} else {
		t.Errorf("supported_versions extension missing")
	}

	// --- 7. supported_groups: X25519, P-256, P-384 (no ML-KEM, no GREASE) ----
	if sg, ok := ch.extData(ExtensionSupportedCurves); ok {
		assertUint16List(t, "supported_groups", sg, []uint16{
			uint16(X25519),
			uint16(CurveP256),
			uint16(CurveP384),
		})
	} else {
		t.Errorf("supported_groups extension missing")
	}

	// --- 8. ec_point_formats: uncompressed -----------------------------------
	if pf, ok := ch.extData(ExtensionSupportedPoints); ok {
		s := cryptobyte.String(pf)
		var formats cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&formats) {
			t.Fatalf("short ec_point_formats")
		}
		if len(formats) != 1 || formats[0] != PointFormatUncompressed {
			t.Errorf("ec_point_formats = %v, want [%d] (uncompressed)", []byte(formats), PointFormatUncompressed)
		}
	} else {
		t.Errorf("ec_point_formats extension missing")
	}

	// --- 9. signature_algorithms: 9, fixed order, rsa_pkcs1_sha1 last --------
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

	// --- 10. ALPN: [h2, http/1.1] --------------------------------------------
	if alpn, ok := ch.extData(ExtensionALPN); ok {
		assertProtocolList(t, "ALPN", alpn, []string{"h2", "http/1.1"})
	} else {
		t.Errorf("ALPN extension missing")
	}

	// --- 11. key_share: single X25519 with a 32-byte public key --------------
	if ks, ok := ch.extData(ExtensionKeyShare); ok {
		s := cryptobyte.String(ks)
		var shares cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&shares) {
			t.Fatalf("short key_share")
		}
		var group uint16
		var pub cryptobyte.String
		if !shares.ReadUint16(&group) || !shares.ReadUint16LengthPrefixed(&pub) {
			t.Fatalf("short key_share entry")
		}
		if group != uint16(X25519) {
			t.Errorf("key_share group = 0x%04x, want X25519 (0x001d)", group)
		}
		if len(pub) != 32 {
			t.Errorf("key_share public key length = %d, want 32", len(pub))
		}
		if !shares.Empty() {
			t.Errorf("key_share has extra entries after X25519")
		}
	} else {
		t.Errorf("key_share extension missing")
	}

	// --- 12. psk_key_exchange_modes: psk_dhe_ke only -------------------------
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

	// --- 13. session_ticket: present, empty body (fresh handshake) -----------
	if st, ok := ch.extData(ExtensionSessionTicket); ok {
		if len(st) != 0 {
			t.Errorf("session_ticket body length = %d, want 0 (fresh handshake)", len(st))
		}
	} else {
		t.Errorf("session_ticket extension missing")
	}

	// --- 14. status_request: OCSP stapling -----------------------------------
	if sr, ok := ch.extData(ExtensionStatusRequest); ok {
		if len(sr) == 0 || sr[0] != statusTypeOCSP {
			t.Errorf("status_request status_type = %v, want %d (OCSP)", sr, statusTypeOCSP)
		}
	} else {
		t.Errorf("status_request extension missing")
	}

	// --- 15. renegotiation_info: empty renegotiated_connection ----------------
	if ri, ok := ch.extData(ExtensionRenegotiationInfo); ok {
		s := cryptobyte.String(ri)
		var reneg cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&reneg) {
			t.Fatalf("short renegotiation_info")
		}
		if len(reneg) != 0 {
			t.Errorf("renegotiation_info has %d bytes, want 0 (initial handshake)", len(reneg))
		}
	} else {
		t.Errorf("renegotiation_info extension missing")
	}
}

// parsedExtTypes returns the extension type sequence of a parsed ClientHello.
func parsedExtTypes(exts []parsedExtension) []uint16 {
	types := make([]uint16, len(exts))
	for i, e := range exts {
		types[i] = e.typ
	}
	return types
}
