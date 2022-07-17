// Copyright 2022 Pavel Petrukhin <merlin>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/ninedraft/gemax/gemax"
	"github.com/ninedraft/gemax/gemax/status"
)

func main() {
	client := gemax.Client{}

	server := gemax.Server{
		Addr: "localhost:1965",
		Handler: func(ctx context.Context, rw gemax.ResponseWriter, req gemax.IncomingRequest) {
			log.Printf("request %s from %s", req.URL(), req.RemoteAddr())
			key := sanitizeKey(req.URL().String())
			if _, err := os.Stat("cache/" + key); err == nil {
				data, errRead := os.ReadFile("cache/" + key)
				if errRead != nil {
					log.Printf("err: %s", err)
					rw.WriteStatus(status.ProxyError, errRead.Error())
					return
				}
				_, _ = rw.Write([]byte("!!! cached !!!\n"))
				_, _ = rw.Write(data)
				return
			}

			resp, err := client.Fetch(ctx, req.URL().String())
			if err != nil {
				log.Printf("err: %s", err)
				rw.WriteStatus(status.ProxyError, err.Error())
				return
			}
			defer resp.Close()

			buf := &bytes.Buffer{}

			rw.WriteStatus(resp.Status, resp.Meta)
			_, _ = io.Copy(io.MultiWriter(buf, rw), resp)

			log.Printf("cache key %q", key)
			if err := os.WriteFile("cache/"+key, buf.Bytes(), 0600); err != nil {
				log.Printf("writing cache file: %v", err)
			}
		},
		Logf: log.Printf,
	}

	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer cancel()

	log.Printf("starting server")
	if err := server.ListenAndServe(ctx, &tls.Config{
		Certificates: []tls.Certificate{
			loadCert(),
		},
	}); err != nil {
		panic(err)
	}
}

var sanitizeKey = strings.NewReplacer(
	"/", "-",
	":", "-",
).Replace

//go:embed certs/*
var certs embed.FS

func loadCert() tls.Certificate {
	var cert, errCertPEM = certs.ReadFile("certs/cert.pem")
	if errCertPEM != nil {
		panic(errCertPEM)
	}
	var key, errKeyPEM = certs.ReadFile("certs/key.pem")
	if errKeyPEM != nil {
		panic(errKeyPEM)
	}
	var c, errPars = tls.X509KeyPair(cert, key)
	if errPars != nil {
		panic(errPars)
	}
	return c
}
