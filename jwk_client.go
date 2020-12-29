package auth0

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"gopkg.in/square/go-jose.v2"
)

var (
	ErrInvalidContentType = errors.New("should have a JSON content type for JWKS endpoint")
	ErrInvalidAlgorithm   = errors.New("algorithm is invalid")
)

type JWKClientOptions struct {
	URI           string
	Client        *http.Client
	KeyIDGetter   KeyIDGetter
	TokenIDGetter TokenIDGetter
}

type JWKS struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

type JWKClient struct {
	keyCacher   KeyCacher
	mu          sync.Mutex
	options     JWKClientOptions
	extractor   RequestTokenExtractor
}

// NewJWKClient creates a new JWKClient instance from the
// provided options.
func NewJWKClient(options JWKClientOptions, extractor RequestTokenExtractor) *JWKClient {
	return NewJWKClientWithCache(options, extractor, nil)
}

// NewJWKClientWithCache creates a new JWKClient instance from the
// provided options and a custom keycacher interface.
// Passing nil to keyCacher will create a persistent key cacher
func NewJWKClientWithCache(options JWKClientOptions, extractor RequestTokenExtractor, keyCacher KeyCacher) *JWKClient {
	if extractor == nil {
		extractor = RequestTokenExtractorFunc(FromHeader)
	}
	if keyCacher == nil {
		keyCacher = newMemoryPersistentKeyCacher()
	}
	if options.Client == nil {
		options.Client = http.DefaultClient
	}
	if options.KeyIDGetter == nil {
		options.KeyIDGetter = KeyIDGetterFunc(DefaultKeyIDGetter)

	}
	if options.TokenIDGetter == nil{
		options.TokenIDGetter = TokenKeyIDGetterFunc(DefaultTokenKeyIDGetter)
	}

	return &JWKClient{
		keyCacher:   keyCacher,
		options:     options,
		extractor:   extractor,
	}
}

// GetKey returns the key associated with the provided ID.
func (j *JWKClient) GetKey(ID string) (jose.JSONWebKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	searchedKey, err := j.keyCacher.Get(ID)
	if err != nil {
		keys, err := j.downloadKeys()
		if err != nil {
			return jose.JSONWebKey{}, err
		}
		addedKey, err := j.keyCacher.AddWithKeyGetter(ID, j.options.KeyIDGetter, keys)
		if err != nil {
			return jose.JSONWebKey{}, err
		}
		return *addedKey, nil
	}

	return *searchedKey, nil
}

func (j *JWKClient) downloadKeys() ([]jose.JSONWebKey, error) {
	fmt.Println("AUTH0 - Downloading keys")
	req, err := http.NewRequest("GET", j.options.URI, new(bytes.Buffer))
	if err != nil {
		return []jose.JSONWebKey{}, err
	}
	resp, err := j.options.Client.Do(req)

	if err != nil {
		return []jose.JSONWebKey{}, err
	}
	defer resp.Body.Close()

	if contentH := resp.Header.Get("Content-Type"); !strings.HasPrefix(contentH, "application/json") {
		return []jose.JSONWebKey{}, ErrInvalidContentType
	}

	var jwks = JWKS{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return []jose.JSONWebKey{}, err
	}

	if len(jwks.Keys) < 1 {
		return []jose.JSONWebKey{}, ErrNoKeyFound
	}

	return jwks.Keys, nil
}

// GetSecret implements the GetSecret method of the SecretProvider interface.
func (j *JWKClient) GetSecret(r *http.Request) (interface{}, error) {
	token, err := j.extractor.Extract(r)
	if err != nil {
		return nil, err
	}

	if len(token.Headers) < 1 {
		return nil, ErrNoJWTHeaders
	}

	keyID := j.options.TokenIDGetter.JWTGet(token)

	return j.GetKey(keyID)
}
