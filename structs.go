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
	"os"
	"time"
)

// Event structs are used to express events via the API
type Event struct {
	//EventID    [32]string `json:"event_id"`		// Generated serverside
	Event     string    `json:"event"`
	FPHash    string    `json:"fp_hash,omitempty"`
	IPVersion string    `json:"ip_version"`
	IPDst     string    `json:"ipv4_dst"`
	IPSrc     string    `json:"ipv4_src"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	TimeStamp time.Time `json:"timestamp"`
	//	TLSVersion  uint16    `json:"tls_version"`  // Part of the fingerprint, doesn't need to be stored here
	SNI string `json:"server_name"`
	//Fingerprint `json:"fingerprint,omitempty"`
}

type userConfig struct {
	MinTLS    string   `json:"min_TLS_ver"`
	Timeout   int64    `json:"timeout"`
	AppLog    string   `json:"appLog"`
	apFile    *os.File // Accompanying file descriptor
	NewFPFile string   `json:"new_fingerprint_file"`
	fpFile    *os.File // Accompanying file descriptor
	EventLog  string   `json:"eventLog"`
	eventFile *os.File // Accompanying file descriptor
}
