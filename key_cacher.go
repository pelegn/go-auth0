package auth0

import (
	"errors"
	"fmt"
	"github.com/devopsfaith/krakend/logging"
	"gopkg.in/square/go-jose.v2/jwt"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

var (
	ErrNoKeyFound = errors.New("no Keys has been found")
	ErrKeyExpired = errors.New("key exists but is expired")

	// Configuring with MaxKeyAgeNoCheck will skip key expiry check
	MaxKeyAgeNoCheck = time.Duration(-1)
	// Configuring with MaxCacheSizeNoCheck will skip key cache size check
	MaxCacheSizeNoCheck = -1
)

type FnJWKKeyID func(*jose.JSONWebKey) string

func JWKKeyID(key *jose.JSONWebKey) string {
	return key.KeyID
}

func JWKKeyIDWithX5t(key *jose.JSONWebKey) string {
	return key.KeyID //+ string(key.CertificateThumbprintSHA1)
}

func JWTKeyID(token *jwt.JSONWebToken) string {
	header := token.Headers[0]
	return header.KeyID
}

func JWTKeyIDWithX5t(token *jwt.JSONWebToken) string {
	header := token.Headers[0]
	return header.KeyID //+ string(header.JSONWebKey.CertificateThumbprintSHA1)
}

type KeyCacher interface {
	Get(keyID string) (*jose.JSONWebKey, error)
	Add(keyID string, webKeys []jose.JSONWebKey) (*jose.JSONWebKey, error)
	AddWithKeyGetter(keyID string, keyGetter KeyIDGetter, webKeys []jose.JSONWebKey) (*jose.JSONWebKey, error)
}

type memoryKeyCacher struct {
	entries      map[string]keyCacherEntry
	maxKeyAge    time.Duration
	maxCacheSize int
	logger       logging.Logger
}

type keyCacherEntry struct {
	addedAt time.Time
	jose.JSONWebKey
}

// NewMemoryKeyCacher creates a new Keycacher interface with option
// to set max age of cached keys and max size of the cache.
func NewMemoryKeyCacher(maxKeyAge time.Duration, maxCacheSize int) KeyCacher {
	return &memoryKeyCacher{
		entries:      map[string]keyCacherEntry{},
		maxKeyAge:    maxKeyAge,
		maxCacheSize: maxCacheSize,
	}
}

func newMemoryPersistentKeyCacher() KeyCacher {
	return &memoryKeyCacher{
		entries:      map[string]keyCacherEntry{},
		maxKeyAge:    MaxKeyAgeNoCheck,
		maxCacheSize: MaxCacheSizeNoCheck,
	}
}

// Get obtains a key from the cache, and checks if the key is expired
func (mkc *memoryKeyCacher) Get(keyID string) (*jose.JSONWebKey, error) {
	searchKey, ok := mkc.entries[keyID]
	fmt.Println("Memory cacher get - ", keyID , "found - ", ok)
	if ok {
		if mkc.maxKeyAge == MaxKeyAgeNoCheck || !mkc.keyIsExpired(keyID) {
			return &searchKey.JSONWebKey, nil
		}
		return nil, ErrKeyExpired
	}
	return nil, ErrNoKeyFound
}

// Add adds a key into the cache and handles overflow
func (mkc *memoryKeyCacher) Add(keyID string, downloadedKeys []jose.JSONWebKey) (*jose.JSONWebKey, error) {
	return mkc.AddWithKeyGetter(keyID, KeyIDGetterFunc(DefaultKeyIDGetter), downloadedKeys)
}

// Add adds a key into the cache and handles overflow, allowing a custom cache-key fn
func (mkc *memoryKeyCacher) AddWithKeyGetter(keyID string, keyGetter KeyIDGetter, downloadedKeys []jose.JSONWebKey) (*jose.JSONWebKey, error) {
	var addingKey jose.JSONWebKey
	fmt.Println("AUTH0 - adding key", keyID)
	for _, key := range downloadedKeys {
		cacheKey := keyGetter.JWKGet(&key)

		if cacheKey == keyID {
			addingKey = key
		}
		if mkc.maxCacheSize == -1 {
			mkc.entries[key.KeyID] = keyCacherEntry{
				addedAt:    time.Now(),
				JSONWebKey: key,
			}
		}
	}
	if addingKey.Key != nil {
		if mkc.maxCacheSize != -1 {
			cacheKey := keyGetter.JWKGet(&addingKey)
			mkc.entries[cacheKey] = keyCacherEntry{
				addedAt:    time.Now(),
				JSONWebKey: addingKey,
			}
			mkc.handleOverflow()
		}
		return &addingKey, nil
	}
	return nil, ErrNoKeyFound
}

// keyIsExpired deletes the key from cache if it is expired
func (mkc *memoryKeyCacher) keyIsExpired(keyID string) bool {
	if time.Now().After(mkc.entries[keyID].addedAt.Add(mkc.maxKeyAge)) {
		delete(mkc.entries, keyID)
		return true
	}
	return false
}

// handleOverflow deletes the oldest key from the cache if overflowed
func (mkc *memoryKeyCacher) handleOverflow() {
	if mkc.maxCacheSize < len(mkc.entries) {
		var oldestEntryKeyID string
		var latestAddedTime = time.Now()
		for entryKeyID, entry := range mkc.entries {
			if entry.addedAt.Before(latestAddedTime) {
				latestAddedTime = entry.addedAt
				oldestEntryKeyID = entryKeyID
			}
		}
		delete(mkc.entries, oldestEntryKeyID)
	}
}
