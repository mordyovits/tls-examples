package main

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"tls-examples/common"
)

var (
	acceptFlag  = flag.String("accept", ":4433", "TCP/IP port to listen on for connections, default :4433")
	dhparamFlag = flag.String("dhparam", "", "DH parameter file to use")
	pskHintFlag = flag.String("psk_hint", "", "PSK identity hint to offer client")
	pskFlag     = flag.String("psk", "", "PSK in hex (without 0x)")
	cipherFlag  = flag.String("cipher", "", "cipher to use")
	certFlag    = flag.String("cert", "", "Certificate file to use, PEM format")
	keyFlag     = flag.String("key", "", "Key file to use, PEM format")
)

func main() {
	flag.Parse()

	conf := tls.Config{}
	conf.InsecureSkipVerify = true

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

	if *dhparamFlag != "" {
		dhp, err := tls.LoadDhParams(*dhparamFlag)
		if err != nil {
			log.Fatal(err)
		}
		conf.DhParameters = &dhp
	}

	if *cipherFlag != "" {
		cipherid, ok := common.CipherMap[*cipherFlag]
		if !ok {
			log.Fatal("unknown cipher:", *cipherFlag)
		}
		conf.CipherSuites = []uint16{cipherid}
	}

	if *pskHintFlag != "" {
		conf.GetPSKIdentityHint = func() ([]byte, error) {
			return []byte(*pskHintFlag), nil
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

	ln, err := tls.Listen("tcp", *acceptFlag, &conf)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed Accept: %v\n", err)
			continue
		}
		go handleConnection(conn)
	}

}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		msg, err := r.ReadBytes(byte('\n'))
		if err != nil {
			if err == io.EOF {
				fmt.Fprintf(os.Stderr, "Client disconnected\n")
				return
			}
			fmt.Fprintf(os.Stderr, "Read err: %v\n", err)
			return
		}
		//println(msg)

		_, err = conn.Write(msg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Write err: %v\n", err)
			return
		}
	}
}
