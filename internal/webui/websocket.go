package webui

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
)

const websocketMagic = "258EAFA5-E914-47DA-95CA-5AB5DFFB7E03"

// Hub manages WebSocket clients and broadcasts findings to all connected clients.
type Hub struct {
	mu      sync.RWMutex
	clients map[net.Conn]struct{}
}

// NewHub creates a new WebSocket hub.
func NewHub() *Hub {
	return &Hub{
		clients: make(map[net.Conn]struct{}),
	}
}

// Broadcast sends findings to all connected WebSocket clients as JSON.
// Non-blocking — slow clients are disconnected.
func (h *Hub) Broadcast(findings []alert.Finding) {
	if len(findings) == 0 {
		return
	}

	data, err := json.Marshal(findings)
	if err != nil {
		return
	}
	frame := buildWSFrame(data)

	h.mu.RLock()
	clients := make([]net.Conn, 0, len(h.clients))
	for conn := range h.clients {
		clients = append(clients, conn)
	}
	h.mu.RUnlock()

	for _, conn := range clients {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(frame); err != nil {
			h.removeClient(conn)
			_ = conn.Close()
		}
	}
}

// ClientCount returns the number of connected WebSocket clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *Hub) addClient(conn net.Conn) {
	h.mu.Lock()
	h.clients[conn] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) removeClient(conn net.Conn) {
	h.mu.Lock()
	delete(h.clients, conn)
	h.mu.Unlock()
}

// HandleWebSocket upgrades an HTTP connection to WebSocket using stdlib only.
func (h *Hub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Validate WebSocket upgrade request
	if r.Header.Get("Upgrade") != "websocket" {
		http.Error(w, "Not a WebSocket request", http.StatusBadRequest)
		return
	}

	// Validate Origin header to prevent cross-origin WebSocket hijacking
	if origin := r.Header.Get("Origin"); origin != "" {
		host := r.Host
		// Allow same-origin connections only
		validOrigins := []string{
			"https://" + host,
			"http://" + host, // during development
		}
		originOK := false
		for _, v := range validOrigins {
			if origin == v {
				originOK = true
				break
			}
		}
		if !originOK {
			http.Error(w, "Origin not allowed", http.StatusForbidden)
			return
		}
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "Missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	// Compute accept key
	hasher := sha1.New()
	hasher.Write([]byte(key + websocketMagic))
	acceptKey := base64.StdEncoding.EncodeToString(hasher.Sum(nil))

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send upgrade response
	resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n\r\n", acceptKey)
	if _, err := bufrw.WriteString(resp); err != nil {
		_ = conn.Close()
		return
	}
	if err := bufrw.Flush(); err != nil {
		_ = conn.Close()
		return
	}

	h.addClient(conn)

	// Read loop — keep connection alive, handle close frames
	go func() {
		defer func() {
			h.removeClient(conn)
			_ = conn.Close()
		}()

		buf := make([]byte, 1024)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 && buf[0]&0x0F == 0x8 {
				return // close frame
			}
			// Send pong for ping frames
			if n > 0 && buf[0]&0x0F == 0x9 {
				pong := []byte{0x8A, 0x00} // pong with no payload
				_, _ = conn.Write(pong)
			}
		}
	}()
}

// buildWSFrame creates a WebSocket text frame from payload bytes.
func buildWSFrame(payload []byte) []byte {
	length := len(payload)
	var frame []byte

	// Opcode 0x1 = text frame, FIN bit set
	frame = append(frame, 0x81)

	switch {
	case length < 126:
		frame = append(frame, byte(length))
	case length < 65536:
		frame = append(frame, 126, byte(length>>8), byte(length))
	default:
		frame = append(frame, 127)
		for i := 7; i >= 0; i-- {
			frame = append(frame, byte(length>>(i*8)))
		}
	}

	frame = append(frame, payload...)
	return frame
}
