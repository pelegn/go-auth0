package auth0

import (
	b64 "encoding/base64"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

//KeyIDGetter extracts a key id from a JSONWebKey
type KeyIDGetter interface {
	JWKGet(*jose.JSONWebKey) string
}

//KeyIDGetterFunc function conforming to the KeyIDGetter interface.
type KeyIDGetterFunc func(*jose.JSONWebKey) string

// Extract calls f(r)
func (f KeyIDGetterFunc) JWKGet(key *jose.JSONWebKey) string {
	return f(key)
}

//DefaultKeyIDGetter returns the default kid as JSONWebKey key id
func DefaultKeyIDGetter(key *jose.JSONWebKey) string {
	return key.KeyID
}

//CompoundSHA1KeyIDGetter extracts the key id from the jSONWebKey as a compound string of the kid and sha1
func CompoundSHA1KeyIDGetter(key *jose.JSONWebKey) string {
	return key.KeyID + b64.RawURLEncoding.EncodeToString(key.CertificateThumbprintSHA1)
}

//TokenIDGetter extracts the keyID from the JSON web token
type TokenIDGetter interface {
	JWTGet(*jwt.JSONWebToken) string
}

//TokenKeyIDGetterFunc function conforming to TokenIDGetter interface
type TokenKeyIDGetterFunc func(*jwt.JSONWebToken) string

// Extract calls f(r)
func (f TokenKeyIDGetterFunc) JWTGet(token *jwt.JSONWebToken) string {
	return f(token)
}

//DefaultTokenKeyIDGetter returns the default kid as the JSONWebKey key id
func DefaultTokenKeyIDGetter(token *jwt.JSONWebToken) string {
		return token.Headers[0].KeyID
}

//CompoundSHA1TokenKeyIDGetter extracts the key id from the jSONWebToken as a compound string of the kid and sha1
func CompoundSHA1TokenKeyIDGetter(token *jwt.JSONWebToken) string {
	x5t, ok := token.Headers[0].ExtraHeaders["x5t"].(string)
	if !ok {
		return token.Headers[0].KeyID
	}
	return token.Headers[0].KeyID + x5t
}
