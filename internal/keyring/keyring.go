// Package keyring stores macarune root keys in a small JSON file. The file
// maps key ids to hex-encoded secrets and is written with 0600 permissions;
// it belongs on the verifier's side only — agents holding tokens never need
// it, which is the whole point of offline attenuation.
package keyring

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"unicode"
)

// KeyLen is the size of generated root keys. 32 bytes matches the
// HMAC-SHA256 block-derived key strength macarune signs with.
const KeyLen = 32

// Key length bounds accepted on load, so hand-provisioned keys of other
// reasonable sizes still work.
const (
	minKeyLen = 16
	maxKeyLen = 64
)

// filePerm keeps the keyring readable by its owner only.
const filePerm fs.FileMode = 0o600

// Keyring is an in-memory set of named root keys.
type Keyring struct {
	keys map[string][]byte
}

// wire is the on-disk JSON layout.
type wire struct {
	Version int               `json:"version"`
	Keys    map[string]string `json:"keys"`
}

// New returns an empty keyring.
func New() *Keyring {
	return &Keyring{keys: map[string][]byte{}}
}

// Load reads a keyring file. A missing file is an error — callers that want
// create-on-demand use LoadOrNew.
func Load(path string) (*Keyring, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var w wire
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("keyring %s: %v", path, err)
	}
	if w.Version != 1 {
		return nil, fmt.Errorf("keyring %s: unsupported version %d", path, w.Version)
	}
	k := New()
	for kid, hexKey := range w.Keys {
		if err := checkKID(kid); err != nil {
			return nil, fmt.Errorf("keyring %s: %v", path, err)
		}
		raw, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, fmt.Errorf("keyring %s: key %q is not hex", path, kid)
		}
		if len(raw) < minKeyLen || len(raw) > maxKeyLen {
			return nil, fmt.Errorf("keyring %s: key %q is %d bytes, want %d-%d",
				path, kid, len(raw), minKeyLen, maxKeyLen)
		}
		k.keys[kid] = raw
	}
	return k, nil
}

// LoadOrNew loads path if it exists and returns an empty keyring otherwise.
func LoadOrNew(path string) (*Keyring, error) {
	k, err := Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		return New(), nil
	}
	return k, err
}

// Save writes the keyring to path with owner-only permissions. An existing
// file is overwritten atomically via a same-directory temp file.
func (k *Keyring) Save(path string) error {
	w := wire{Version: 1, Keys: map[string]string{}}
	for kid, raw := range k.keys {
		w.Keys[kid] = hex.EncodeToString(raw)
	}
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dirOf(path), ".keyring-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(filePerm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// dirOf returns the directory portion of path, defaulting to ".".
func dirOf(path string) string {
	i := strings.LastIndexByte(path, os.PathSeparator)
	if i < 0 {
		return "."
	}
	if i == 0 {
		return string(os.PathSeparator)
	}
	return path[:i]
}

// Generate creates a fresh random key under kid. It refuses to overwrite an
// existing key: rotating a root key silently would orphan every token minted
// under it, so replacement must be an explicit Remove + Generate.
func (k *Keyring) Generate(kid string) ([]byte, error) {
	if err := checkKID(kid); err != nil {
		return nil, err
	}
	if _, exists := k.keys[kid]; exists {
		return nil, fmt.Errorf("key %q already exists (remove it first to rotate)", kid)
	}
	raw := make([]byte, KeyLen)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	k.keys[kid] = raw
	return raw, nil
}

// Add installs externally provisioned key material under kid.
func (k *Keyring) Add(kid string, raw []byte) error {
	if err := checkKID(kid); err != nil {
		return err
	}
	if len(raw) < minKeyLen || len(raw) > maxKeyLen {
		return fmt.Errorf("key %q is %d bytes, want %d-%d", kid, len(raw), minKeyLen, maxKeyLen)
	}
	if _, exists := k.keys[kid]; exists {
		return fmt.Errorf("key %q already exists", kid)
	}
	k.keys[kid] = append([]byte(nil), raw...)
	return nil
}

// Remove deletes the key under kid; removing an absent key is an error so
// typos in rotation scripts are loud.
func (k *Keyring) Remove(kid string) error {
	if _, exists := k.keys[kid]; !exists {
		return fmt.Errorf("no key %q in keyring", kid)
	}
	delete(k.keys, kid)
	return nil
}

// Key returns the key material for kid.
func (k *Keyring) Key(kid string) ([]byte, error) {
	raw, exists := k.keys[kid]
	if !exists {
		return nil, fmt.Errorf("no key %q in keyring", kid)
	}
	return raw, nil
}

// KIDs lists key ids in sorted order for deterministic output.
func (k *Keyring) KIDs() []string {
	out := make([]string, 0, len(k.keys))
	for kid := range k.keys {
		out = append(out, kid)
	}
	sort.Strings(out)
	return out
}

// checkKID mirrors the token package's identifier rules.
func checkKID(kid string) error {
	if kid == "" {
		return fmt.Errorf("key id is empty")
	}
	if len(kid) > 128 {
		return fmt.Errorf("key id longer than 128 bytes")
	}
	if strings.IndexFunc(kid, unicode.IsSpace) >= 0 {
		return fmt.Errorf("key id %q contains whitespace", kid)
	}
	return nil
}
