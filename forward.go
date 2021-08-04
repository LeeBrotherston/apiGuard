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
	"io"
	"log"
	"net"
	"strings"

	dactyloscopy "github.com/LeeBrotherston/dactyloscopy"
)

// forward handles an individual connection
func forward(conn net.Conn, destination string, fingerprintDBNew map[uint64]string) {
	buf := make([]byte, 1024)
	var chLen uint16

	log.Printf("Starting forward function")

	// Grab some data in the buffer
	_, err := conn.Read(buf)
	check(err)

	if buf[0] == 22 && buf[5] == 1 && buf[1] == 3 && buf[9] == 3 {
		log.Printf("About to call tlsFingerprint")
		fingerprintOutput, _, _ := dactyloscopy.TLSFingerprint(buf, fingerprintDBNew)
		log.Printf("Fingerptintoutoutoutout: %v", fingerprintOutput)

		chLen = uint16(buf[3])<<8 + uint16(buf[4])
		// Check if the host is in the blocklist or not...
		//t := time.Now()
		hostname := string(strings.SplitN(string(destination), ":", 2)[0])
		_, ok := blocklist[hostname]
		if ok == true {
			log.Printf("%v is on the blocklist!  DROPPING!\n", hostname)
			//fmt.Fprintf(globalConfig.eventFile, "{ \"timestamp\": \"%v\", \"event\": \"block\", \"fingerprint_desc\": \"%v\", \"server_name\": \"%v\" }\n", t.Format(time.RFC3339), fingerprintOutput.FingerprintName, hostname)
			// Just unceremoniously drop the connection, because lol.
			conn.Close()
		} else {
			// Not on the blocklist - woo!
			// XXX DO THIS!
			log.Printf("%v is *not* on the blocklist.  Permitting\n", hostname)
			//fmt.Fprintf(globalConfig.eventFile, "{ \"timestamp\": \"%v\", \"event\": \"permit\", \"fingerprint_desc\": \"%v\", \"server_name\": \"%v\" }\n", t.Format(time.RFC3339), fingerprintOutput.FingerprintName, hostname)
		}

	} else {
		// This doesn't look like TLS.... DROP IT ON THE FLOOR!
		conn.Close()
		return
	}
	log.Printf("Say what? %v - %v", destination, destination)

	log.Printf("Time to connect?")
	// OK Destination is determined, let's do some connecting!
	//client, err := net.DialTimeout("tcp", destination, time.Duration(connectTimeout))
	client, err := net.Dial("tcp", destination)

	if err != nil {
		// Could not connect, burn it all down!!!
		defer conn.Close()
		log.Printf("Dial to '%v' failed: %v", destination, err)
		return
	}

	// Actually route some packets (ok forward them), yo!
	// ... and transmit the buffer that we already processed
	client.Write(buf[0 : chLen+5])

	// Default buffer is 32K...  This lets us play with different sizes
	forwardBuf := make([]byte, 65535)

	go func() {
		defer client.Close()
		defer conn.Close()
		io.CopyBuffer(client, conn, forwardBuf)

	}()
	go func() {
		defer client.Close()
		defer conn.Close()
		io.CopyBuffer(conn, client, forwardBuf)

	}()

}
