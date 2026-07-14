// Tests for keyring persistence: generation, save/load round trips, file
// permissions, and rejection of malformed files. All I/O stays in t.TempDir.
package keyring

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateProducesDistinct32ByteKeys(t *testing.T) {
	k := New()
	a, err := k.Generate("root")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := k.Generate("ci")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(a) != KeyLen || len(b) != KeyLen {
		t.Fatalf("key lengths %d/%d, want %d", len(a), len(b), KeyLen)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two generated keys must differ")
	}
}

func TestGenerateRefusesToOverwrite(t *testing.T) {
	// Silent rotation would orphan every outstanding token under that kid.
	k := New()
	if _, err := k.Generate("root"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := k.Generate("root"); err == nil {
		t.Fatal("regenerating an existing kid should fail")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	k := New()
	orig, _ := k.Generate("root")
	if err := k.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, err := loaded.Key("root")
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatal("loaded key differs from generated key")
	}
}

func TestSaveWritesOwnerOnlyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "keys.json")
	k := New()
	k.Generate("root")
	if err := k.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("keyring file mode %o, want 600", perm)
	}
}

func TestLoadOrNewOnMissingFile(t *testing.T) {
	k, err := LoadOrNew(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("LoadOrNew: %v", err)
	}
	if len(k.KIDs()) != 0 {
		t.Fatalf("expected empty keyring, got %v", k.KIDs())
	}
}

func TestLoadRejectsMalformedFiles(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"not JSON":       "hello",
		"wrong version":  `{"version":2,"keys":{}}`,
		"unknown field":  `{"version":1,"keys":{},"extra":true}`,
		"non-hex key":    `{"version":1,"keys":{"root":"zzzz"}}`,
		"too-short key":  `{"version":1,"keys":{"root":"abcd"}}`,
		"whitespace kid": `{"version":1,"keys":{"my key":"` + hex64() + `"}}`,
	}
	for name, content := range cases {
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("%s: Load should fail", name)
		}
	}
}

// hex64 returns a valid 32-byte key in hex for fixture files.
func hex64() string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = "0123456789abcdef"[i%16]
	}
	return string(b)
}

func TestAddAndRemove(t *testing.T) {
	k := New()
	raw := bytes.Repeat([]byte{0xAB}, 32)
	if err := k.Add("imported", raw); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := k.Add("imported", raw); err == nil {
		t.Fatal("duplicate Add should fail")
	}
	if err := k.Add("tiny", []byte{1, 2, 3}); err == nil {
		t.Fatal("undersized key should be rejected")
	}
	if err := k.Remove("imported"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := k.Remove("imported"); err == nil {
		t.Fatal("removing an absent kid should fail loudly")
	}
}

func TestAddCopiesKeyMaterial(t *testing.T) {
	// A caller mutating its slice after Add must not corrupt the ring.
	k := New()
	raw := bytes.Repeat([]byte{0x01}, 32)
	k.Add("root", raw)
	raw[0] = 0xFF
	got, _ := k.Key("root")
	if got[0] != 0x01 {
		t.Fatal("Add must defensively copy the key")
	}
}

func TestKIDsAreSorted(t *testing.T) {
	k := New()
	for _, kid := range []string{"zeta", "alpha", "mid"} {
		if _, err := k.Generate(kid); err != nil {
			t.Fatalf("Generate(%s): %v", kid, err)
		}
	}
	kids := k.KIDs()
	if kids[0] != "alpha" || kids[1] != "mid" || kids[2] != "zeta" {
		t.Fatalf("KIDs not sorted: %v", kids)
	}
}
