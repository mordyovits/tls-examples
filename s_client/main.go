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

	"tls-examples/common"
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

func tlsCipherSuiteToString(cipherid uint16) string {
	name, ok := common.CipherReverseMap[cipherid]
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
		cipherid, ok := common.CipherMap[*cipherFlag]
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
