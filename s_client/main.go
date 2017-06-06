package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

var (
	connectFlag     = flag.String("connect", ":4433", "host and port to connect to, default :4433")
	pskIdentityFlag = flag.String("psk_identity", "", "PSK identity")
	pskFlag         = flag.String("psk", "", "PSK in hex (without 0x)")
	cipherFlag      = flag.String("cipher", "", "cipher to use")
	servernameFlag  = flag.String("servername", "", "Set TLS extension servername in ClientHello")
	certFlag        = flag.String("cert", "", "Certificate file to use, PEM format")
	keyFlag         = flag.String("key", "", "Key file to use, PEM format")
)

// the golang/tls name
var standardCipherMap = map[string]uint16{
	"TLS_RSA_WITH_RC4_128_SHA":                  0x0005,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":             0x000a,
	"TLS_RSA_WITH_AES_128_CBC_SHA":              0x002f,
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA":          0x0033,
	"TLS_DH_anon_WITH_AES_128_CBC_SHA":          0x0034,
	"TLS_RSA_WITH_AES_256_CBC_SHA":              0x0035,
	"TLS_DHE_RSA_WITH_AES_256_CBC_SHA":          0x0039,
	"TLS_DH_anon_WITH_AES_256_CBC_SHA":          0x003a,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":           0x003c,
	"TLS_RSA_WITH_AES_256_CBC_SHA256":           0x003d,
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256":       0x0067,
	"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256":       0x006b,
	"TLS_DH_anon_WITH_AES_128_CBC_SHA256":       0x006c,
	"TLS_DH_anon_WITH_AES_256_CBC_SHA256":       0x006d,
	"TLS_PSK_WITH_AES_128_CBC_SHA":              0x008C,
	"TLS_PSK_WITH_AES_256_CBC_SHA":              0x008D,
	"TLS_DHE_PSK_WITH_AES_128_CBC_SHA":          0x0090,
	"TLS_DHE_PSK_WITH_AES_256_CBC_SHA":          0x0091,
	"TLS_RSA_PSK_WITH_AES_128_CBC_SHA":          0x0094,
	"TLS_RSA_PSK_WITH_AES_256_CBC_SHA":          0x0095,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":           0x009c,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":           0x009d,
	"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256":       0x009e,
	"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384":       0x009f,
	"TLS_DH_anon_WITH_AES_128_GCM_SHA256":       0x00a6,
	"TLS_DH_anon_WITH_AES_256_GCM_SHA384":       0x00a7,
	"TLS_PSK_WITH_AES_128_GCM_SHA256":           0x00a8,
	"TLS_PSK_WITH_AES_256_GCM_SHA384":           0x00a9,
	"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256":       0x00aa,
	"TLS_DHE_PSK_WITH_AES_256_GCM_SHA384":       0x00ab,
	"TLS_RSA_PSK_WITH_AES_128_GCM_SHA256":       0x00ac,
	"TLS_RSA_PSK_WITH_AES_256_GCM_SHA384":       0x00ad,
	"TLS_PSK_WITH_AES_128_CBC_SHA256":           0x00ae,
	"TLS_DHE_PSK_WITH_AES_128_CBC_SHA256":       0x00b2,
	"TLS_RSA_PSK_WITH_AES_128_CBC_SHA256":       0x00b6,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":          0xc007,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":      0xc009,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":      0xc00a,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":            0xc011,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":       0xc012,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":        0xc013,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":        0xc014,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":   0xc023,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":     0xc027,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":     0xc02f,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":   0xc02b,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":     0xc030,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":   0xc02c,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":      0xcca8,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":    0xcca9,
	"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xccaa,
	"TLS_PSK_WITH_CHACHA20_POLY1305_SHA256":     0xccab,
	"TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256": 0xccad,
	"TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256": 0xccae,
}

// the openssl name
var openSSLCipherMap = map[string]uint16{
	"RC4-SHA":                       0x0005,
	"DES-CBC3-SHA":                  0x000a,
	"AES128-SHA":                    0x002f,
	"DHE-RSA-AES128-SHA":            0x0033,
	"ADH-AES128-SHA":                0x0034,
	"AES256-SHA":                    0x0035,
	"DHE-RSA-AES256-SHA":            0x0039,
	"ADH-AES256-SHA":                0x003a,
	"AES128-SHA256":                 0x003c,
	"AES256-SHA256":                 0x003d,
	"DHE-RSA-AES128-SHA256":         0x0067,
	"DHE-RSA-AES256-SHA256":         0x006b,
	"ADH-AES128-SHA256":             0x006c,
	"ADH-AES256-SHA256":             0x006d,
	"PSK-AES128-CBC-SHA":            0x008c,
	"PSK-AES256-CBC-SHA":            0x008d,
	"DHE-PSK-AES128-CBC-SHA":        0x0090,
	"DHE-PSK-AES256-CBC-SHA":        0x0091,
	"RSA-PSK-AES128-CBC-SHA":        0x0094,
	"RSA-PSK-AES256-CBC-SHA":        0x0095,
	"AES128-GCM-SHA256":             0x009c,
	"AES256-GCM-SHA384":             0x009d,
	"DHE-RSA-AES128-GCM-SHA256":     0x009e,
	"DHE-RSA-AES256-GCM-SHA384":     0x009f,
	"ADH-AES128-GCM-SHA256":         0x00a6,
	"ADH-AES256-GCM-SHA384":         0x00a7,
	"PSK-AES128-GCM-SHA256":         0x00a8,
	"PSK-AES256-GCM-SHA384":         0x00a9,
	"DHE-PSK-AES128-GCM-SHA256":     0x00aa,
	"DHE-PSK-AES256-GCM-SHA384":     0x00ab,
	"RSA-PSK-AES128-GCM-SHA256":     0x00ac,
	"RSA-PSK-AES256-GCM-SHA384":     0x00ad,
	"PSK-AES128-CBC-SHA256":         0x00ae,
	"DHE-PSK-AES128-CBC-SHA256":     0x00b2,
	"RSA-PSK-AES128-CBC-SHA256":     0x00b6,
	"ECDHE-ECDSA-RC4-SHA":           0xc007,
	"ECDHE-ECDSA-AES128-SHA":        0xc009,
	"ECDHE-ECDSA-AES256-SHA":        0xc00a,
	"ECDHE-RSA-RC4-SHA":             0xc011,
	"ECDHE-RSA-DES-CBC3-SHA":        0xc012,
	"ECDHE-RSA-AES128-SHA":          0xc013,
	"ECDHE-RSA-AES256-SHA":          0xc014,
	"ECDHE-ECDSA-AES128-SHA256":     0xc023,
	"ECDHE-RSA-AES128-SHA256":       0xc027,
	"ECDHE-RSA-AES128-GCM-SHA256":   0xc02f,
	"ECDHE-ECDSA-AES128-GCM-SHA256": 0xc02b,
	"ECDHE-RSA-AES256-GCM-SHA384":   0xc030,
	"ECDHE-ECDSA-AES256-GCM-SHA384": 0xc02c,
	"ECDHE-RSA-CHACHA20-POLY1305":   0xcca8,
	"ECDHE-ECDSA-CHACHA20-POLY1305": 0xcca9,
	"DHE-RSA-CHACHA20-POLY1305":     0xccaa,
	"PSK-CHACHA20-POLY1305":         0xccab,
	"DHE-PSK-CHACHA20-POLY1305":     0xccad,
	"RSA-PSK-CHACHA20-POLY1305":     0xccae,
}

func tlsVersionToString(version uint16) string {
	switch version {
	case 0x0301:
		return "TLSv1.0"
	case 0x0302:
		return "TLSv1.1"
	case 0x0303:
		return "TLSv1.2"
	default:
		return "UnknownTLSVersion"
	}
}

var cipherMap map[string]uint16
var cipherReverseMap map[uint16]string

func init() {
	// a combined standard+openssl names map
	cipherMap = make(map[string]uint16)
	// a reverse of cipherMap
	cipherReverseMap = make(map[uint16]string)

	for k, v := range standardCipherMap {
		cipherReverseMap[v] = k
		cipherMap[k] = v
	}
	for k, v := range openSSLCipherMap {
		cipherMap[k] = v
	}
}

func tlsCipherSuiteToString(cipherid uint16) string {
	name, ok := cipherReverseMap[cipherid]
	if !ok {
		return "UnknownCipher"
	}
	return name
}

func logConnectionState(conn *tls.Conn) {
	state := conn.ConnectionState()
	if state.DidResume {
		fmt.Fprintf(os.Stderr, "Resumed, ")
	} else {
		fmt.Fprintf(os.Stderr, "New, ")
	}
	fmt.Fprintf(os.Stderr, "%s, ", tlsVersionToString(state.Version))
	fmt.Fprintf(os.Stderr, "Cipher is %s\n", tlsCipherSuiteToString(state.CipherSuite))
	if len(state.PeerCertificates) > 0 {
		serverpub := state.PeerCertificates[0].PublicKey
		switch pub := serverpub.(type) {
		case *rsa.PublicKey:
			fmt.Fprintf(os.Stderr, "Server public key is RSA %d bits\n", pub.N.BitLen())
		case *dsa.PublicKey:
			fmt.Println("Server public key is of type DSA\n")
		case *ecdsa.PublicKey:
			fmt.Println("Server public key is of type ECDSA\n")
		default:
			panic("unknown type of public key")
		}

		//fmt.Fprintf(os.Stderr, "Server Subject: %s\n", state.PeerCertificates[0].Subject)

	}
	if state.NegotiatedProtocol != "" {
		fmt.Fprintf(os.Stderr, "Negotiated protocol is %s, ", state.NegotiatedProtocol)
		if state.NegotiatedProtocolIsMutual {
			fmt.Fprintf(os.Stderr, "(mutual)\n")
		} else {
			fmt.Fprintf(os.Stderr, "(NOT mutual)\n")
		}
	}
	fmt.Fprintf(os.Stderr, "---\n")
}

func main() {
	flag.Parse()

	conf := tls.Config{}
	conf.InsecureSkipVerify = true

	if *servernameFlag != "" {
		conf.ServerName = *servernameFlag
	}

	if *certFlag != "" {
		if *keyFlag != "" {
			cert, err := tls.LoadX509KeyPair(*certFlag, *keyFlag)
			if err != nil {
				log.Fatal(err)
			}
			conf.Certificates = []tls.Certificate{cert}
		} else {
			log.Fatal("missing key paramater")
		}
	}

	if *cipherFlag != "" {
		cipherid, ok := cipherMap[*cipherFlag]
		if !ok {
			log.Fatal("unknown cipher:", *cipherFlag)
		}
		conf.CipherSuites = []uint16{cipherid}
	}

	if *pskIdentityFlag != "" {
		conf.GetPSKIdentity = func(hint []byte) (string, error) {
			return *pskIdentityFlag, nil
		}
	}

	if *pskFlag != "" {
		psk, err := hex.DecodeString(*pskFlag)
		if err != nil {
			log.Fatal("bad psk: ", err)
		}
		conf.GetPSKKey = func(identity string) ([]byte, error) {
			return psk, nil
		}
	}

	dialStart := time.Now()
	conn, err := tls.Dial("tcp", *connectFlag, &conf)
	dialEnd := time.Now()
	if err != nil {
		log.Fatal("failed to connect: " + err.Error())
	}
	// TODO -quiet
	fmt.Fprintf(os.Stderr, "tls.Dial() took: %s\n", dialEnd.Sub(dialStart))
	logConnectionState(conn)

	c := make(chan int64)

	copy := func(r io.ReadCloser, w io.WriteCloser) {
		defer func() {
			r.Close()
			w.Close()
		}()
		n, err := io.Copy(w, r)
		if err != nil {
			log.Println(err)
		}
		c <- n
	}

	go copy(conn, os.Stdout)
	go copy(os.Stdin, conn)

	<-c
	return
}
