package keyringutil

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/zalando/go-keyring"
)

// windowsLimit is the per-entry limit of Windows Credential Manager, which
// the fake keyring enforces
const windowsLimit = 2560

// fakeKeyring is an in-memory keyring that limits the size of each entry
type fakeKeyring struct {
	mu      sync.Mutex
	entries map[string]string
	failSet string // service name for which Set fails
}

func key(service, user string) string {
	return service + "\x00" + user
}

func (k *fakeKeyring) Set(service, user, password string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if len(password) > windowsLimit {
		return keyring.ErrSetDataTooBig
	}
	if service == k.failSet {
		return errors.New("set failed")
	}
	k.entries[key(service, user)] = password

	return nil
}

func (k *fakeKeyring) Get(service, user string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	v, ok := k.entries[key(service, user)]
	if !ok {
		return "", keyring.ErrNotFound
	}

	return v, nil
}

func (k *fakeKeyring) Delete(service, user string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if _, ok := k.entries[key(service, user)]; !ok {
		return keyring.ErrNotFound
	}
	delete(k.entries, key(service, user))

	return nil
}

// count returns the number of entries stored
func (k *fakeKeyring) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()

	return len(k.entries)
}

// useFake replaces the backend with a fake keyring for the test
func useFake(t *testing.T) *fakeKeyring {
	t.Helper()

	fake := &fakeKeyring{entries: make(map[string]string)}
	orig := backend
	backend = fake
	t.Cleanup(func() { backend = orig })

	return fake
}

// value returns a value of n bytes that differs at every position, so parts
// that are reordered or truncated are detected
func value(n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "%d,", i)
	}

	return b.String()[:n]
}

const (
	service = "test-service"
	user    = "test-user"
)

func TestSetGet(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantParts int // 0 when stored as a single entry
	}{
		{"empty", "", 0},
		{"small", "a refresh token", 0},
		{"chunk size", value(ChunkSize), 0},
		{"just over chunk size", value(ChunkSize + 1), 2},
		{"over windows limit", value(windowsLimit + 1), 2},
		{"large", value(10 * 1024), 6},
		{"small value that looks like a header", headerPrefix + "1:abc", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := useFake(t)

			if err := Set(service, user, tt.value); err != nil {
				t.Fatalf("Set() error = %v", err)
			}

			got, err := Get(service, user)
			if err != nil {
				t.Fatalf("Get() error = %v", err)
			}
			if got != tt.value {
				t.Errorf("Get() returned %d bytes that do not match the %d bytes stored", len(got), len(tt.value))
			}

			// the main entry plus one entry per part
			if want := 1 + tt.wantParts; fake.count() != want {
				t.Errorf("stored %d entries, want %d", fake.count(), want)
			}

			main, _ := fake.Get(service, user)
			if isHeader := strings.HasPrefix(main, headerPrefix); isHeader != (tt.wantParts > 0) {
				t.Errorf("main entry is a header = %v, want %v", isHeader, tt.wantParts > 0)
			}
		})
	}
}

func TestGet_ExistingEntry(t *testing.T) {
	fake := useFake(t)

	// an entry stored directly with go-keyring, such as by a previous version
	if err := fake.Set(service, user, "existing value"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, err := Get(service, user)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != "existing value" {
		t.Errorf("Get() = %q, want %q", got, "existing value")
	}
}

func TestSet_Replace(t *testing.T) {
	tests := []struct {
		name          string
		first, second string
	}{
		{"large with small", value(10 * 1024), "small"},
		{"small with large", "small", value(10 * 1024)},
		{"large with fewer parts", value(10 * 1024), value(3000)},
		{"large with more parts", value(3000), value(10 * 1024)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := useFake(t)

			if err := Set(service, user, tt.first); err != nil {
				t.Fatalf("Set() first error = %v", err)
			}
			if err := Set(service, user, tt.second); err != nil {
				t.Fatalf("Set() second error = %v", err)
			}

			got, err := Get(service, user)
			if err != nil {
				t.Fatalf("Get() error = %v", err)
			}
			if got != tt.second {
				t.Errorf("Get() did not return the second value")
			}

			// no parts are left over from the first value
			want := 1
			if len(tt.second) > ChunkSize {
				want += len(split(tt.second))
			}
			if fake.count() != want {
				t.Errorf("stored %d entries, want %d", fake.count(), want)
			}
		})
	}
}

func TestSet_Errors(t *testing.T) {
	t.Run("too large", func(t *testing.T) {
		fake := useFake(t)

		err := Set(service, user, value(maxParts*ChunkSize+1))
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("Set() error = %v, want %v", err, ErrTooLarge)
		}
		if fake.count() != 0 {
			t.Errorf("stored %d entries, want 0", fake.count())
		}
	})

	t.Run("largest value", func(t *testing.T) {
		fake := useFake(t)

		want := value(maxParts * ChunkSize)
		if err := Set(service, user, want); err != nil {
			t.Fatalf("Set() error = %v", err)
		}
		if fake.count() != 1+maxParts {
			t.Errorf("stored %d entries, want %d", fake.count(), 1+maxParts)
		}

		got, err := Get(service, user)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got != want {
			t.Errorf("Get() did not return the stored value")
		}
	})

	t.Run("too large keeps existing value", func(t *testing.T) {
		fake := useFake(t)

		if err := Set(service, user, value(5000)); err != nil {
			t.Fatalf("Set() error = %v", err)
		}
		before := fake.count()

		if err := Set(service, user, value(maxParts*ChunkSize+1)); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Set() error = %v, want %v", err, ErrTooLarge)
		}

		// nothing is written or removed for a rejected value
		if fake.count() != before {
			t.Errorf("stored %d entries, want %d", fake.count(), before)
		}
		got, err := Get(service, user)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got != value(5000) {
			t.Errorf("Get() did not return the existing value")
		}
	})

	t.Run("part fails keeps existing value", func(t *testing.T) {
		fake := useFake(t)

		if err := Set(service, user, "existing"); err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		fake.failSet = partService(service, 2)
		if err := Set(service, user, value(5000)); err == nil {
			t.Fatalf("Set() error = nil, want error")
		}

		// the header is only written once all parts are stored
		got, err := Get(service, user)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got != "existing" {
			t.Errorf("Get() = %q, want existing value %q", got, "existing")
		}
	})
}

func TestGet_Errors(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		useFake(t)

		if _, err := Get(service, user); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get() error = %v, want %v", err, ErrNotFound)
		}
	})

	// setup stores a value in 3 parts and returns the fake keyring
	setup := func(t *testing.T) *fakeKeyring {
		t.Helper()

		fake := useFake(t)
		if err := Set(service, user, value(5000)); err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		return fake
	}

	tests := []struct {
		name   string
		damage func(fake *fakeKeyring)
	}{
		{"missing part", func(fake *fakeKeyring) {
			_ = fake.Delete(partService(service, 2), user)
		}},
		{"modified part", func(fake *fakeKeyring) {
			_ = fake.Set(partService(service, 2), user, value(ChunkSize-1)+"x")
		}},
		{"invalid header", func(fake *fakeKeyring) {
			_ = fake.Set(service, user, headerPrefix+"not a header")
		}},
		{"invalid number of parts", func(fake *fakeKeyring) {
			_ = fake.Set(service, user, headerPrefix+"0:abc")
		}},
		{"too many parts", func(fake *fakeKeyring) {
			_ = fake.Set(service, user, fmt.Sprintf("%s%d:abc", headerPrefix, maxParts+1))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := setup(t)
			tt.damage(fake)

			_, err := Get(service, user)
			if !errors.Is(err, ErrNotFound) || !errors.Is(err, ErrIncomplete) {
				t.Errorf("Get() error = %v, want %v and %v", err, ErrNotFound, ErrIncomplete)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	t.Run("value in parts", func(t *testing.T) {
		fake := useFake(t)
		if err := Set(service, user, value(10*1024)); err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		if err := Delete(service, user); err != nil {
			t.Fatalf("Delete() error = %v", err)
		}
		if fake.count() != 0 {
			t.Errorf("stored %d entries after Delete(), want 0", fake.count())
		}
		if _, err := Get(service, user); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get() error = %v, want %v", err, ErrNotFound)
		}
	})

	t.Run("not found", func(t *testing.T) {
		useFake(t)

		if err := Delete(service, user); !errors.Is(err, ErrNotFound) {
			t.Errorf("Delete() error = %v, want %v", err, ErrNotFound)
		}
	})

	t.Run("parts without a header", func(t *testing.T) {
		fake := useFake(t)
		_ = fake.Set(partService(service, 1), user, "orphan")
		_ = fake.Set(partService(service, 2), user, "orphan")

		if err := Delete(service, user); !errors.Is(err, ErrNotFound) {
			t.Errorf("Delete() error = %v, want %v", err, ErrNotFound)
		}
		if fake.count() != 0 {
			t.Errorf("stored %d entries after Delete(), want 0", fake.count())
		}
	})

	t.Run("other values are kept", func(t *testing.T) {
		fake := useFake(t)
		if err := Set(service, user, value(5000)); err != nil {
			t.Fatalf("Set() error = %v", err)
		}
		if err := Set("other-service", user, value(5000)); err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		if err := Delete(service, user); err != nil {
			t.Fatalf("Delete() error = %v", err)
		}
		if _, err := Get("other-service", user); err != nil {
			t.Errorf("Get() other value error = %v", err)
		}
		if fake.count() != 1+len(split(value(5000))) {
			t.Errorf("stored %d entries, want only the other value", fake.count())
		}
	})
}
