// Copyright (c) 2018 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/crypto/ocsp"

	"github.com/urfave/cli"
)

func readCertificate(path string) (*x509.Certificate, error) {
	log.Printf("Loading certificate from %s", path)

	certificatePEMData, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	certificateDERData, _ := pem.Decode(certificatePEMData)

	if certificateDERData == nil {
		return nil, errors.New("Unable to decode PEM data from certificate")
	}

	certificate, err := x509.ParseCertificate(certificateDERData.Bytes)

	if err != nil {
		return nil, err
	}

	return certificate, nil
}

func fetchOCSPResponse(ocspURL string, subject, issuer *x509.Certificate) (*ocsp.Response, error) {
	url, err := url.Parse(ocspURL)

	if err != nil {
		return nil, err
	}

	buffer, err := ocsp.CreateRequest(subject, issuer, nil)

	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost, ocspURL, bytes.NewBuffer(buffer))

	if err != nil {
		return nil, err
	}

	request.Header.Add("Accept", "application/ocsp-response")
	request.Header.Add("Content-Type", "application/ocsp-request")
	request.Header.Add("Host", url.Host)

	client := &http.Client{}

	response, err := client.Do(request)

	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	result, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return nil, err
	}

	ocsp, err := ocsp.ParseResponse(result, issuer)

	if err != nil {
		return nil, err
	}

	return ocsp, nil
}

func commandFetch(c *cli.Context) error {
	if c.NArg() < 2 {
		return errors.New("Missing argument: <subject certificate path> <issuer certificate path>")
	}

	subjectPath := c.Args().Get(0)
	issuerPath := c.Args().Get(1)

	subject, err := readCertificate(subjectPath)

	if err != nil {
		return err
	}

	issuer, err := readCertificate(issuerPath)

	if err != nil {
		return err
	}

	receivedResponse := false

	for i := range subject.OCSPServer {
		server := subject.OCSPServer[i]

		log.Printf("Trying OCSP server at %s", server)
		ocspResponse, err := fetchOCSPResponse(server, subject, issuer)

		if err != nil {
			log.Printf("Unable to fetch OCSP information: %s", err)
			continue
		}

		receivedResponse = true
		log.Printf("Response:")

		statusStr := ocsp.ResponseStatus(ocspResponse.Status)

		log.Printf("  Status: %s (%d)", statusStr, ocspResponse.Status)
		log.Printf("  Serial: %s", ocspResponse.SerialNumber)
		log.Printf("  Next update: %s", ocspResponse.NextUpdate)
		log.Printf("  This update: %s", ocspResponse.ThisUpdate)
		log.Printf("  Produced at: %s", ocspResponse.ProducedAt)

		if ocspResponse.Status == ocsp.Revoked {
			log.Printf("  Revoked at:  %s", ocspResponse.RevokedAt)
			log.Printf("  Revocation Reason: %d", ocspResponse.RevocationReason)
		} else {
			log.Printf("  Revoked at:  N/A")
		}
	}

	if !receivedResponse {
		return errors.New("Unable to fetch OCSP from any servers. Giving up.")
	}

	return nil
}
