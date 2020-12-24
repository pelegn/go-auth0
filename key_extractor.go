package auth0

import (
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type KeyIDGetter interface {
	JWKGet(*jose.JSONWebKey) string
	//JWTGet(*jwt.JSONWebToken) string
}

type KeyGetterFunc func(*jose.JSONWebKey) string

// Extract calls f(r)
func (f KeyGetterFunc) JWKGet(key *jose.JSONWebKey) string {
	return f(key)
}

func DefaultKeyIDGetter(key *jose.JSONWebKey) string {
	return key.KeyID
}

type TokenKeyIDGetterFunc func(*jwt.JSONWebToken) string

// Extract calls f(r)
func (f TokenKeyIDGetterFunc) JWTGet(token *jwt.JSONWebToken) string {
	return f(token)
}

func DefaultTokenKeyIDGetter(key *jose.JSONWebKey) string {
	return key.KeyID
}
