/*
 * apns.go
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
	"net"
	"crypto/tls"
	"encoding/binary"
	"gob"
	"json"
	"bytes"
)

const (
	ReleasePushGateway = "gateway.push.apple.com:2195"
	SandboxPushGateway = "gateway.sandbox.push.apple.com:2195"
)

type Error struct {
	status uint32
}

const errorStrings []string = []string{
	"No error",
	"Processing error",
	"Missing device token",
	"Missing topic",
	"Missing payload",
	"Invalid token size",
	"Invalid topic size",
	"Invalid payload size",
	"Invalid token",
}

func (e *Error) String() string {
	switch {
	case e.status <= len(errorStrings):
		return errorStrings[e.status]
	default:
		return "Unknown error"
	}
}

type result struct {
	status     byte
	identifier uint32
}

type Apns struct {
	conn           *tls.Conn
	revocationList []string
	waitReplies    map[uint32]chan result
}

func replyServer(apns *Apns) {
	buf := make([]byte, 25)
	for {
		n, err := apns.conn.Read(buf)
		if err != nil && err != os.EAGAIN {
			log.Fatal("replyServer:", err)
		}
		if n >= 6 {
			var r reply
			r.status = buf[0]
			r.identifier = wire.Uint32(buf[1:])

			// send the reply to anyone waiting for a response
			ch := apns.waitReplies[r.identifier]
			if ch != nil {
				ch <- r
			}
		}
	}
}

func NewConnection(addr string) (*Apns, os.Error) {
	conn, err := newConnection(addr, "cert.pem", "pkey.pem")
	if err != nil {
		return nil, err
	}

	apns := &Apns{conn: conn}
	err = apns.loadRevocationList()
	if err != nil {
		return nil, err
	}
	return apns, nil
}

func (a *Apns) loadRevocationList() os.Error {
	f, err := os.Open("revocationList", os.WRONLY|os.O_CREATE|os.O_APPEND, 0544)
	if err != nil {
		log.Fatal("apns.loadRecovationList:", err)
	}
	defer f.Close()

	if a.revocationList == nil {
		a.revocationList = make([]string, 5)
	}

	d := gob.NewDecoder(f)
	for err == nil {
		var s string
		if err = d.Decode(&s); err == nil {
			a.revocationList = append(a.revocationList, s)
		}
	}
	if err == os.EOF {
		return nil
	}
	return err
}

func (a *Apns) SendMessage(identifier, expiry uint32, token []byte, payload interface{}) (<-chan *os.Error, os.Error) {
	buf := make([]byte, 256).(*buffer)

	if identifier == 0 && expiry == 0 {
		// use simple format
		buf.writeByte(0)
	} else {
		// use extended format
		buf.writeByte(1)
		buf.writeUint32(identifier)
		buf.writeUint32(expiry)
	}

	// append the token
	buf.writeUint16(uint16(len(token)))
	buf.write(token)

	// build the JSON data
	rawJson, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	// compact it (requires a bytes.Buffer to store the compacted version)
	jbuf := &bytes.Buffer{}
	err = json.Compact(jbuf, rawJson)
	if err != nil {
		return nil, err
	}

	// write the JSOB payload into the command buffer
	buf.writeUint32(uint32(jbuf.Len()))
	buf.write(jbuf.Bytes())

	// all done-- now send it!
	var sent int = 0
	l := len(buf)
	for sent < l {
		n, err = a.conn.Write(buf[sent:l])
		if err != nil {
			return nil, err
		}
		sent += n
	}

	// sent successfully, return a channel which will funnel the result back asynchronously
	errchan := make(chan *os.Error)

	if identifier != 0 {
		if a.waitReplies == nil {
			a.waitReplies = make(map[uint32]chan result)
		}
		a.waitReplies[identifier] = make(chan result, 1)

		go func() {
			var r result
			select {
			case r = <-a.waitReplies[identifier]:
				if r.status != 0 {
					// send an error
					errchan <- *Error{r.status}
				} else {
					errchan <- nil
				}
			}
		}()
	}

	return errchan, nil
}
