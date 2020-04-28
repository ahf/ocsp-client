// Copyright (c) 2018 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"os"

	"github.com/urfave/cli"
)

func main() {
	app := &cli.App{
		Name:    "ocsp-client",
		Usage:   "OCSP Client Utility.",
		Version: VERSION,
		Authors: []*cli.Author{
			&cli.Author{
				Name:  "Alexander Færøy",
				Email: "ahf@0x90.dk",
			},
		},
		Copyright: "(c) 2018 Alexander Færøy.",
		Commands: []*cli.Command{
			{
				Name:   "fetch",
				Usage:  "Fetch an OCSP document.",
				Action: commandFetch,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "insecure",
						Usage: "Allow insecure TLS connections",
					},
				},
			},
		},
		UseShortOptionHandling: true,
	}

	err := app.Run(os.Args)

	if err != nil {
		log.Fatal(err)
	}
}
