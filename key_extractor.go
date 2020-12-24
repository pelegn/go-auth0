package auth0

import (
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type KeyIDGetter interface {
	JWKGet(*jose.JSONWebKey) string
}

type KeyGetterFunc func(*jose.JSONWebKey) string

// Extract calls f(r)
func (f KeyGetterFunc) JWKGet(key *jose.JSONWebKey) string {
	return f(key)
}

func DefaultKeyIDGetter(key *jose.JSONWebKey) string {
	return key.KeyID + string(key.CertificateThumbprintSHA1)
}

type TokenIDGetter interface {
	JWTGet(*jwt.JSONWebToken) string
}

type TokenKeyIDGetterFunc func(*jwt.JSONWebToken) string

// Extract calls f(r)
func (f TokenKeyIDGetterFunc) JWTGet(token *jwt.JSONWebToken) string {
	return f(token)
}

func DefaultTokenKeyIDGetter(token *jwt.JSONWebToken) string {
	x5t, ok := token.Headers[0].ExtraHeaders["x5t"].(string)
	if !ok {
		return token.Headers[0].KeyID
	}
	return token.Headers[0].KeyID + x5t
}
