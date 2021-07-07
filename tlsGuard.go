/*

Exciting Licence Info.....

This file is part of tlsGuard.

# Lee's Shitheads Prohibited Licence (loosely based on the BSD simplified licence)
Copyright 2021 Lee Brotherston
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. You are not a member of law enforcement, and you do not work for any government or private organization that conducts or aids surveillance (e.g., signals intelligence, Palantir).
4. You are not associated with any groups which are aligned with Racist, Homophobic, Transphobic, TERF, Mysogynistic, "Pro Life" (anti-womens-choice), or other shithead values.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


*/

package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/LeeBrotherston/dactyloscopy"  // Super cool package by someguy(tm) for TLS Fingerprinting
)

// Global blocklist map (temp)
var blocklist = map[string]bool{}

func main() {
	// Check commandline options
	var fpJSON = flag.String("fingerprint", "./tlsproxy.json", "the fingerprint file")
	var listenAddress = flag.String("listen", "127.0.0.1:8080", "address for proxy to listen to")
	flag.Parse()

	// Open JSON file tlsproxy.json
	file, err := ioutil.ReadFile(*fpJSON)
	if err != nil {
		log.Printf("Problem: File error opening fingerprint file: %v\n", err)
		log.Printf("You may wish to try: cat fingerprints.json | jq -scM '' > tlsProxy.json to update\n")
		os.Exit(1)
	}

	// Parse that JSON file
	var jsontype []dactyloscopy.FingerprintFile
	err = json.Unmarshal(file, &jsontype)
    check(err)


	// Create the bare fingerprintDB map structure
	fingerprintDBNew := make(map[uint64]string)

	// populate the fingerprintDB map
	for k := range jsontype {
		dactyloscopy.Add(dactyloscopy.Ftop(jsontype[k]), fingerprintDBNew)
	}
	log.Printf("Loaded %v fingerprints\n", len(jsontype))

	// Setup Listener
	listener, err := net.Listen("tcp", *listenAddress)
    check(err)

	// Loop to handle new connections
	for {
		log.Printf("Listener for loooooooop")
		conn, err := listener.Accept()
        check(err)
		go forward(conn, fingerprintDBNew)
	}

}

// check is a (probably over) simple function to wrap errors that will always be fatal
func check(e error) {
	if e != nil {
		panic(e)
	}
}
