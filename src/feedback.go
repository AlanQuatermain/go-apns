/*
 * feedback.go
 * go-apns
 * 
 * Created by Jim Dovey on 16/08/2011.
 * 
 * Copyright (c) 2011 Jim Dovey
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the project's author nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

package apns

import (
	"os"
	"time"
	"crypto/tls"
)

var quitChan chan chan bool = make(chan chan bool, 1)
var addresses = map[bool]string{
	true:  "feedback.sandbox.push.apple.com",
	false: "feedback.push.apple.com",
}

func feedbackMonitor(config *tls.Config, useSandbox bool) {
	for {
		timer := time.NewTimer(5 * 60 * 1000000000) // five minutes
		select {
		case ch := <-quitChan:
			// been told to quit
			ch <- true
			return
		case <-timer.C:
			// timer fired, talk to the feedback server
			conn, err := tls.Dial("tcp", addresses[useSandbox], config)
			if err != nil {
				log.Println("Failed to dial feedback server:", err)
				break
			}

			// once connected, the server immediately sends us our data
			var buf [38]byte
			for {
				n, err := conn.Read(buf[:])
				if err != nil {
					if err != os.EOF {
						log.Println("Failed to read feedback message:", err)
					}
					break
				}

				// four-byte time, in seconds
				time_unused := wire.Uint32(buf[0:])
				// two byte token size (always 32)
				size_unused := wire.Uint16(buf[4:])

				// get the device token itself
				var token DeviceToken
				copy(token[:], buf[6:])

				// store the token in the revocation list
				revokeDeviceToken(token)
			}

			conn.Close()
		}
	}
}

func startFeedbackMonitor(certPath, keyPath string, useSandbox bool) os.Error {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}

	config := &tls.Config{Certificates: []Certificate{cert}}
	go feedbackMonitor(config, useSandbox)
	return nil
}

func stopFeedbackMonitor() {
	ch := make(chan bool, 1)
	// tell the goroutine to stop
	quitChan <- ch
	// wait for it to do so
	<-ch
}
