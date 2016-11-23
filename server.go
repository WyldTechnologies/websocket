// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"bufio"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	handshakeHead  = ""
	compressHeader = ""

	headerConnection             = "Connection"
	headerUpgrade                = "Upgrade"
	headerSecWebSocketProtocol   = "Sec-Websocket-Protocol"
	headerSecWebSocketExtensions = "Sec-Websocket-Extensions"
	headerSecWebSocketVersion    = "Sec-Websocket-Version"
	headerSecWebSocketKey        = "Sec-Websocket-Key"
)

// HandshakeError describes an error with the handshake from the peer.
type HandshakeError struct {
	message string
}

func (e HandshakeError) Error() string { return e.message }

// Upgrader specifies parameters for upgrading an HTTP connection to a
// WebSocket connection.
type Upgrader struct {
	// HandshakeTimeout specifies the duration for the handshake to complete.
	HandshakeTimeout time.Duration

	// ReadBufferSize and WriteBufferSize specify I/O buffer sizes. If a buffer
	// size is zero, then a default value of 4096 is used. The I/O buffer sizes
	// do not limit the size of the messages that can be sent or received.
	ReadBufferSize, WriteBufferSize int

	// Subprotocols specifies the server's supported protocols in order of
	// preference. If this field is set, then the Upgrade method negotiates a
	// subprotocol by selecting the first match in this list with a protocol
	// requested by the client.
	Subprotocols []string

	// Error specifies the function for generating HTTP error responses. If Error
	// is nil, then http.Error is used to generate the HTTP response.
	Error func(w http.ResponseWriter, r *http.Request, status int, reason error)

	// CheckOrigin returns true if the request Origin header is acceptable. If
	// CheckOrigin is nil, the host in the Origin header must not be set or
	// must match the host of the request.
	CheckOrigin func(r *http.Request) bool

	// EnableCompression specify if the server should attempt to negotiate per
	// message compression (RFC 7692). Setting this value to true does not
	// guarantee that compression will be supported. Currently only "no context
	// takeover" modes are supported.
	EnableCompression bool
}

func (u *Upgrader) returnError(w http.ResponseWriter, r *http.Request, status int, err error) {
	if u.Error != nil {
		u.Error(w, r, status, err)
	} else {
		w.Header().Set(headerSecWebSocketVersion, "13")
		http.Error(w, http.StatusText(status), status)
	}
}

// checkSameOrigin returns true if the origin is not set or is equal to the request host.
func checkSameOrigin(r *http.Request) bool {
	origin := r.Header["Origin"]
	if len(origin) == 0 {
		return true
	}
	u, err := url.Parse(origin[0])
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

func (u *Upgrader) selectSubprotocol(r *http.Request, responseHeader http.Header) string {
	if u.Subprotocols != nil {
		clientProtocols := Subprotocols(r)
		for _, serverProtocol := range u.Subprotocols {
			for _, clientProtocol := range clientProtocols {
				if clientProtocol == serverProtocol {
					return clientProtocol
				}
			}
		}
	} else if responseHeader != nil {
		return responseHeader.Get(headerSecWebSocketProtocol)
	}
	return ""
}

var (
	ErrHandshakeNonGet           = HandshakeError{"websocket: method not GET"}
	ErrHandshakeVersion          = HandshakeError{"websocket: version != 13"}
	ErrHandshakeExtUnsupported   = HandshakeError{"websocket: application specific Sec-Websocket-Extensions headers are unsupported"}
	ErrHandshakeHeaderConnection = HandshakeError{"websocket: could not find connection header with token 'upgrade'"}
	ErrHandshakeHeaderUpgrade    = HandshakeError{"websocket: could not find upgrade header with token 'websocket'"}
	ErrHandshakeOrigin           = HandshakeError{"websocket: origin not allowed"}
	ErrHandshakeSecKey           = HandshakeError{"websocket: key missing or blank"}
	ErrHandshakeHijacker         = HandshakeError{"websocket: response does not implement http.Hijacker"}
	ErrHandshakeReadNonEmpty     = HandshakeError{"websocket: client sent data before handshake is complete"}
)

// UpgradeConn upgrades the HTTP server connection to the WebSocket protocol.
// It returns plain net.Conn instance, that could be wrapped in Conn.
func (u *Upgrader) UpgradeConn(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (conn net.Conn, subprotocol string, compress bool, err error) {
	if r.Method != "GET" {
		err = ErrHandshakeNonGet
		u.returnError(w, r, http.StatusMethodNotAllowed, err)
		return
	}

	if _, ok := responseHeader[headerSecWebSocketExtensions]; ok {
		err = ErrHandshakeExtUnsupported
		u.returnError(w, r, http.StatusInternalServerError, err)
		return
	}

	if !tokenListContainsValue(r.Header, headerSecWebSocketVersion, "13") {
		err = ErrHandshakeVersion
		u.returnError(w, r, http.StatusBadRequest, err)
		return
	}
	if !tokenListContainsValue(r.Header, headerConnection, "upgrade") {
		err = ErrHandshakeHeaderConnection
		u.returnError(w, r, http.StatusBadRequest, err)
		return
	}
	if !tokenListContainsValue(r.Header, headerUpgrade, "websocket") {
		err = ErrHandshakeHeaderUpgrade
		u.returnError(w, r, http.StatusBadRequest, err)
		return
	}

	checkOrigin := u.CheckOrigin
	if checkOrigin == nil {
		checkOrigin = checkSameOrigin
	}
	if !checkOrigin(r) {
		err = ErrHandshakeOrigin
		u.returnError(w, r, http.StatusForbidden, err)
		return
	}

	challengeKey := r.Header.Get(headerSecWebSocketKey)
	if challengeKey == "" {
		err = ErrHandshakeSecKey
		u.returnError(w, r, http.StatusBadRequest, err)
		return
	}

	h, ok := w.(http.Hijacker)
	if !ok {
		err = ErrHandshakeHijacker
		u.returnError(w, r, http.StatusInternalServerError, err)
		return
	}

	var rw *bufio.ReadWriter
	conn, rw, err = h.Hijack()
	if err != nil {
		u.returnError(w, r, http.StatusInternalServerError, err)
		return
	}
	if rw.Reader.Buffered() > 0 {
		conn.Close()
		err = ErrHandshakeReadNonEmpty
		return
	}

	subprotocol = u.selectSubprotocol(r, responseHeader)
	compress = u.selectCompression(r)

	// Clear deadlines set by HTTP server.
	conn.SetDeadline(time.Time{})
	if u.HandshakeTimeout > 0 {
		conn.SetWriteDeadline(time.Now().Add(u.HandshakeTimeout))
	}
	if err = u.returnOk(rw, subprotocol, computeAcceptKey(challengeKey), compress, responseHeader); err != nil {
		conn.Close()
		return
	}
	if u.HandshakeTimeout > 0 {
		conn.SetWriteDeadline(time.Time{})
	}

	return
}

func writeString(err *error, rw *bufio.ReadWriter, str string) {
	if *err == nil {
		_, *err = rw.WriteString(str)
	}
}
func writeByte(err *error, rw *bufio.ReadWriter, b byte) {
	if *err == nil {
		*err = rw.WriteByte(b)
	}
}

func (u *Upgrader) returnOk(rw *bufio.ReadWriter, subprotocol, challengeKey string, compress bool, responseHeader http.Header) (err error) {
	writeString(&err, rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ")
	writeString(&err, rw, challengeKey)
	writeString(&err, rw, "\r\n")
	if subprotocol != "" {
		writeString(&err, rw, headerSecWebSocketProtocol)
		writeString(&err, rw, ": ")
		writeString(&err, rw, subprotocol)
		writeString(&err, rw, "\r\n")
	}
	if compress {
		writeString(&err, rw, headerSecWebSocketExtensions)
		writeString(&err, rw, ": permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n")
	}
	for k, vs := range responseHeader {
		if k == headerSecWebSocketProtocol {
			continue
		}
		for _, v := range vs {
			writeString(&err, rw, k)
			writeString(&err, rw, ": ")
			for i := 0; i < len(v); i++ {
				b := v[i]
				if b <= 31 {
					// prevent response splitting.
					b = ' '
				}
				writeByte(&err, rw, b)
			}
			writeString(&err, rw, "\r\n")
		}
	}
	writeString(&err, rw, "\r\n")

	if err == nil {
		err = rw.Flush()
	}

	return
}

func (u *Upgrader) selectCompression(r *http.Request) bool {
	// Negotiate PMCE
	if u.EnableCompression {
		for _, ext := range parseExtensions(r.Header) {
			if ext[""] != "permessage-deflate" {
				continue
			}
			return true
		}
	}
	return false
}

// Upgrade upgrades the HTTP server connection to the WebSocket protocol.
//
// The responseHeader is included in the response to the client's upgrade
// request. Use the responseHeader to specify cookies (Set-Cookie) and the
// application negotiated subprotocol (Sec-Websocket-Protocol).
//
// If the upgrade fails, then Upgrade replies to the client with an HTTP error
// response.
func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (*Conn, error) {
	netConn, subprotocol, compress, err := u.UpgradeConn(w, r, responseHeader)
	if err != nil {
		return nil, err
	}

	c := newConn(netConn, true, u.ReadBufferSize, u.WriteBufferSize)
	c.subprotocol = subprotocol
	if compress {
		c.newCompressionWriter = compressNoContextTakeover
		c.newDecompressionReader = decompressNoContextTakeover
	}

	return c, nil
}

// Upgrade upgrades the HTTP server connection to the WebSocket protocol.
//
// This function is deprecated, use websocket.Upgrader instead.
//
// The application is responsible for checking the request origin before
// calling Upgrade. An example implementation of the same origin policy is:
//
//	if req.Header.Get("Origin") != "http://"+req.Host {
//		http.Error(w, "Origin not allowed", 403)
//		return
//	}
//
// If the endpoint supports subprotocols, then the application is responsible
// for negotiating the protocol used on the connection. Use the Subprotocols()
// function to get the subprotocols requested by the client. Use the
// Sec-Websocket-Protocol response header to specify the subprotocol selected
// by the application.
//
// The responseHeader is included in the response to the client's upgrade
// request. Use the responseHeader to specify cookies (Set-Cookie) and the
// negotiated subprotocol (Sec-Websocket-Protocol).
//
// The connection buffers IO to the underlying network connection. The
// readBufSize and writeBufSize parameters specify the size of the buffers to
// use. Messages can be larger than the buffers.
//
// If the request is not a valid WebSocket handshake, then Upgrade returns an
// error of type HandshakeError. Applications should handle this error by
// replying to the client with an HTTP error response.
func Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header, readBufSize, writeBufSize int) (*Conn, error) {
	u := Upgrader{ReadBufferSize: readBufSize, WriteBufferSize: writeBufSize}
	u.Error = func(w http.ResponseWriter, r *http.Request, status int, reason error) {
		// don't return errors to maintain backwards compatibility
	}
	u.CheckOrigin = func(r *http.Request) bool {
		// allow all connections by default
		return true
	}
	return u.Upgrade(w, r, responseHeader)
}

// Subprotocols returns the subprotocols requested by the client in the
// Sec-Websocket-Protocol header.
func Subprotocols(r *http.Request) []string {
	h := strings.TrimSpace(r.Header.Get(headerSecWebSocketProtocol))
	if h == "" {
		return nil
	}
	protocols := strings.Split(h, ",")
	for i := range protocols {
		protocols[i] = strings.TrimSpace(protocols[i])
	}
	return protocols
}

// IsWebSocketUpgrade returns true if the client requested upgrade to the
// WebSocket protocol.
func IsWebSocketUpgrade(r *http.Request) bool {
	return tokenListContainsValue(r.Header, headerConnection, "upgrade") &&
		tokenListContainsValue(r.Header, headerUpgrade, "websocket")
}
