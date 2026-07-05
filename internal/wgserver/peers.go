package wgserver

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Peer represents a WireGuard client peer.
type Peer struct {
	Name       string    `json:"name"`
	PublicKey  string    `json:"public_key"`
	PrivateKey string    `json:"private_key"`
	AllowedIP  string    `json:"allowed_ip"`
	CreatedAt  time.Time `json:"created_at"`
}

// PeerStore manages persistent storage of peers.
type PeerStore struct {
	mu       sync.RWMutex
	peers    []*Peer
	filePath string
}

// NewPeerStore creates a new peer store.
func NewPeerStore(filePath string) *PeerStore {
	return &PeerStore{
		filePath: filePath,
		peers:    make([]*Peer, 0),
	}
}

// Load reads peers from the JSON file.
func (ps *PeerStore) Load() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	data, err := os.ReadFile(ps.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No peers file yet
		}
		return fmt.Errorf("reading peers file: %w", err)
	}

	var peers []*Peer
	if err := json.Unmarshal(data, &peers); err != nil {
		return fmt.Errorf("parsing peers file: %w", err)
	}

	ps.peers = peers
	return nil
}

// Save writes peers to the JSON file.
func (ps *PeerStore) Save() error {
	data, err := json.MarshalIndent(ps.peers, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling peers: %w", err)
	}
	return os.WriteFile(ps.filePath, data, 0600)
}

// Add adds a new peer and persists.
func (ps *PeerStore) Add(peer *Peer) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	peer.CreatedAt = time.Now()
	ps.peers = append(ps.peers, peer)
	return ps.Save()
}

// Remove removes a peer by name and persists.
func (ps *PeerStore) Remove(name string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	for i, p := range ps.peers {
		if p.Name == name {
			ps.peers = append(ps.peers[:i], ps.peers[i+1:]...)
			return ps.Save()
		}
	}
	return fmt.Errorf("peer %q not found", name)
}

// Get returns a peer by name.
func (ps *PeerStore) Get(name string) *Peer {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	for _, p := range ps.peers {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// List returns all peers.
func (ps *PeerStore) List() []Peer {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	result := make([]Peer, len(ps.peers))
	for i, p := range ps.peers {
		result[i] = *p
	}
	return result
}
