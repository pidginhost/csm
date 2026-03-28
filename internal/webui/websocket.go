package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
)

// Hub manages WebSocket clients and broadcasts findings to all connected clients.
type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]context.CancelFunc
}

// NewHub creates a new WebSocket hub.
func NewHub() *Hub {
	return &Hub{
		clients: make(map[*websocket.Conn]context.CancelFunc),
	}
}

// Broadcast sends findings to all connected WebSocket clients as JSON.
func (h *Hub) Broadcast(findings []alert.Finding) {
	if len(findings) == 0 {
		return
	}

	data, err := json.Marshal(findings)
	if err != nil {
		return
	}

	h.mu.RLock()
	clients := make(map[*websocket.Conn]context.CancelFunc, len(h.clients))
	for conn, cancel := range h.clients {
		clients[conn] = cancel
	}
	h.mu.RUnlock()

	for conn := range clients {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := conn.Write(ctx, websocket.MessageText, data)
		cancel()
		if err != nil {
			h.removeClient(conn)
			_ = conn.Close(websocket.StatusGoingAway, "write failed")
		}
	}
}

// ClientCount returns the number of connected WebSocket clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *Hub) addClient(conn *websocket.Conn, cancel context.CancelFunc) {
	h.mu.Lock()
	h.clients[conn] = cancel
	h.mu.Unlock()
}

func (h *Hub) removeClient(conn *websocket.Conn) {
	h.mu.Lock()
	if cancel, ok := h.clients[conn]; ok {
		cancel()
		delete(h.clients, conn)
	}
	h.mu.Unlock()
}

// HandleWebSocket upgrades an HTTP connection to WebSocket.
func (h *Hub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// No origin check — auth is handled by cookie in handleWSFindings
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	h.addClient(conn, cancel)

	// Read loop — keeps connection alive, handles close frames
	go func() {
		defer func() {
			h.removeClient(conn)
			_ = conn.Close(websocket.StatusNormalClosure, "")
		}()

		for {
			// Read with timeout — if no message in 60s, client is gone
			readCtx, readCancel := context.WithTimeout(ctx, 60*time.Second)
			_, _, err := conn.Read(readCtx)
			readCancel()
			if err != nil {
				return
			}
		}
	}()

	// Send a ping every 30s to keep the connection alive
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
				err := conn.Ping(pingCtx)
				pingCancel()
				if err != nil {
					return
				}
			}
		}
	}()
}
