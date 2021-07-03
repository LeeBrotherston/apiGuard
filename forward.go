package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	dactyloscopy "github.com/LeeBrotherston/dactyloscopy"
)

// forward handles an individual connection
func forward(conn net.Conn, fingerprintDBNew map[uint64]string) {

	buf := make([]byte, 1024)
	proxyDest := ""
	var destination []byte
	var chLen uint16

	log.Printf("Starting forward function")
	// Loop until the destination is determined, then connect to it
	// XXX does not account for getting stuck in a shitty loop pre-connect
	// Need to de-loop this
	for len(destination) == 0 {
		// Grab some data in the buffer
		_, err := conn.Read(buf)

		check(err)

		if buf[0] == 22 && buf[5] == 1 && buf[1] == 3 && buf[9] == 3 {
			log.Printf("About to call tlsFingerprint")
			fingerprintOutput, _, _ := dactyloscopy.TLSFingerprint(buf, proxyDest, fingerprintDBNew)
			log.Printf("Fingerptintoutoutoutout: %v", fingerprintOutput)
			destination = fingerprintOutput.Destination

			chLen = uint16(buf[3])<<8 + uint16(buf[4])
			// Check if the host is in the blocklist or not...
			t := time.Now()
			hostname := string(strings.SplitN(string(destination), ":", 2)[0])
			_, ok := blocklist[hostname]
			if ok == true {
				log.Printf("%v is on the blocklist!  DROPPING!\n", hostname)
				fmt.Fprintf(globalConfig.eventFile, "{ \"timestamp\": \"%v\", \"event\": \"block\", \"fingerprint_desc\": \"%v\", \"server_name\": \"%v\" }\n", t.Format(time.RFC3339), fingerprintOutput.FingerprintName, hostname)
				conn.Close()
			} else {
				// Not on the blocklist - woo!
				// XXX DO THIS!
				log.Printf("%v is *not* on the blocklist.  Permitting\n", hostname)
				fmt.Fprintf(globalConfig.eventFile, "{ \"timestamp\": \"%v\", \"event\": \"permit\", \"fingerprint_desc\": \"%v\", \"server_name\": \"%v\" }\n", t.Format(time.RFC3339), fingerprintOutput.FingerprintName, hostname)
			}

		} else {
			defer conn.Close()
			//log.Printf("%s Disconnected\n", conn.RemoteAddr())
			return
		}
		log.Printf("Say what? %v - %v", destination, proxyDest)
	}

	log.Printf("Time to connect?")
	// OK Destination is determined, let's do some connecting!
	client, err := net.DialTimeout("tcp", proxyDest, time.Duration(globalConfig.Timeout))

	if err != nil {
		// Could not connect, burn it all down!!!
		defer conn.Close()
		log.Printf("Dial to '%v' failed: %v", proxyDest, err)
		return
	}

	// Actually route some packets (ok proxy them), yo!
	// ... and transmit the buffer that we already processed (or a reconstructed one)
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
