/*

Exciting Licence Info.....

This file is part of tlsProxy.

tlsProxy is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

tlsProxy is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with tlsProxy.  If not, see <http://www.gnu.org/licenses/>.

Exciting Licence Info Addendum.....

tlsProxy is additionally released under the "don't judge me" program
whereby it is forbidden to rip into me too harshly for programming
mistakes, kthnxbai.

*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/LeeBrotherston/dactyloscopy"
)

// Fingerprints can totally be converted using jq -scM ''
// WWWWHHHHHAAAAAAATTTTT?!

// G-G-G-G-GLOBAL VARS ..... probably bad.... whateevveeerrr

// Transport (pool) for connections to API
var restClient *http.Client
var developer bool

// Global blocklist map (temp)
var blocklist = map[string]bool{}

// Global counter for new fingerprints
//var tempFPCounter int
var globalConfig userConfig

// { "timestamp": "2016-08-09 15:09:08", "event": "fingerprint_match", "ip_version": "ipv6", "ipv6_src": "2607:fea8:705f:fd86::105a", "ipv6_dst": "2607:f8b0:400b:80b::2007", "src_port": 51948, "dst_port": 443, "tls_version": "TLSv1.2", "fingerprint_desc": "Chrome 51.0.2704.84 6", "server_name": "chatenabled.mail.google.com" }

func main() {
	// Check commandline config options
	var fpJSON = flag.String("fingerprint", "./tlsproxy.json", "the fingerprint file")
	var listenAddress = flag.String("listen", "127.0.0.1:8080", "address for proxy to listen to")
	var config = flag.String("config", "./config.json", "location of config file")
	//var interfaceName = flag.String("interface", "", "Specify the interface")
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
	if err != nil {
		log.Fatalf("JSON error: %v", err)
		os.Exit(1)
	}

	// Create the bare fingerprintDB map structure
	fingerprintDBNew := make(map[uint64]string)

	// populate the fingerprintDB map
	for k := range jsontype {
		dactyloscopy.Add(dactyloscopy.Ftop(jsontype[k]), fingerprintDBNew)
	}

	log.Printf("Loaded %v fingerprints\n", len(jsontype))

	// Load the config file config.json
	// Open JSON file
	fileConfig, err := ioutil.ReadFile(*config)
	if err != nil {
		fmt.Printf("Problem: File error opening config file: %v\n", err)
		os.Exit(1)
	}

	// Parse that JSON file
	err = json.Unmarshal(fileConfig, &globalConfig)
	if err != nil {
		fmt.Printf("JSON error: %v", err)
		os.Exit(1)
	}

	// Setup Listener
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		log.Fatalf("Failed to setup listener: %v", err)
		os.Exit(1)
	}

	// Loop to handle new connections
	for {
		log.Printf("Listener for loooooooop")
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("ERROR: failed to accept listener: %v", err)
			os.Exit(1)
		}
		go forward(conn, fingerprintDBNew)
	}

}

// check is a (probably over) simple function to wrap errors that will always be fatal
func check(e error) {
	if e != nil {
		panic(e)
	}
}
