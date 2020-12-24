package auth0

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func genTestConfiguration(configuration Configuration, token string) (*JWTValidator, *http.Request) {
	validator := NewValidator(configuration, nil, nil)

	req, _ := http.NewRequest("", "http://localhost", nil)
	authHeader := fmt.Sprintf("Bearer %s", token)
	req.Header.Add("Authorization", authHeader)

	return validator, req
}

func invalidProvider(token *jwt.JSONWebToken) (interface{}, error) {
	return nil, errors.New("invalid secret provider")
}

func TestValidateRequestAndClaims(t *testing.T) {
	tests := []struct {
		name string
		// validator config
		configuration Configuration
		// token attr
		token string
		// test result
		expectedErrorMsg string
	}{
		{
			name: "pass - token HS256",
			configuration: NewConfiguration(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			expectedErrorMsg: "",
		},
		{
			name: "pass - token ES384",
			configuration: NewConfiguration(
				defaultSecretProviderES384,
				defaultAudience,
				defaultIssuer,
				jose.ES384,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.ES384,
				defaultSecretES384,
			),
			expectedErrorMsg: "",
		},
		{
			name: "pass - token, config empty iss, aud",
			configuration: NewConfiguration(
				defaultSecretProvider,
				emptyAudience,
				emptyIssuer,
				jose.HS256,
			),
			token: getTestToken(
				emptyAudience,
				emptyIssuer,
				time.Now().Add(24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			expectedErrorMsg: "",
		},
		{
			name: "pass - token HS256 config no enforce sig alg",
			configuration: NewConfigurationTrustProvider(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			expectedErrorMsg: "",
		},
		{
			name: "pass - token ES384 config no enforce sig alg",
			configuration: NewConfigurationTrustProvider(
				defaultSecretProviderES384,
				defaultAudience,
				defaultIssuer,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.ES384,
				defaultSecretES384,
			),
			expectedErrorMsg: "",
		},
		{
			name: "fail - config no enforce sig alg but invalid token alg",
			configuration: NewConfigurationTrustProvider(
				defaultSecretProviderES384,
				defaultAudience,
				defaultIssuer,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.RS256,
				defaultSecretRS256,
			),
			expectedErrorMsg: "error in cryptographic primitive",
		},
		{
			name: "fail - invalid config secret provider",
			configuration: NewConfiguration(
				SecretProviderFunc(invalidProvider),
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			expectedErrorMsg: "invalid secret provider",
		},
		{
			name: "fail - invalid token aud",
			configuration: NewConfiguration(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				[]string{"invalid aud"},
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			expectedErrorMsg: "invalid audience claim (aud)",
		},
		{
			name: "fail - invalid token iss",
			configuration: NewConfiguration(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				defaultAudience,
				"invalid iss",
				time.Now().Add(24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			expectedErrorMsg: "invalid issuer claim (iss)",
		},
		{
			name: "fail - invalid token expiry",
			configuration: NewConfiguration(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(-24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			expectedErrorMsg: "token is expired (exp)",
		},
		{
			name: "fail - invalid token alg",
			configuration: NewConfiguration(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(-24*time.Hour),
				jose.HS384,
				defaultSecret,
			),
			expectedErrorMsg: "algorithm is invalid",
		},
		{
			name: "fail - invalid token secret",
			configuration: NewConfiguration(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.HS256,
				[]byte("invalid secret"),
			),
			expectedErrorMsg: "error in cryptographic primitive",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator, req := genTestConfiguration(test.configuration, test.token)

			jwt, err := validator.ValidateRequest(req)

			if test.expectedErrorMsg != "" {
				if err == nil {
					t.Errorf("Validation should have failed with error with substring: " + test.expectedErrorMsg)
				} else if !strings.Contains(err.Error(), test.expectedErrorMsg) {
					t.Errorf("Validation should have failed with error with substring: " + test.expectedErrorMsg + ", but got: " + err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Validation should not have failed with error, but got: " + err.Error())
				}

				// claims should be unmarshalled successfully
				claims := map[string]interface{}{}
				err = validator.Claims(jwt, &claims)
				if err != nil {
					t.Errorf("Claims unmarshall should not have failed with error, but got: " + err.Error())
				}
			}
		})
	}
}

func TestValidateRequestAndClaimsWithLeeway(t *testing.T) {
	tests := []struct {
		name string
		// validator config
		configuration Configuration
		// token attr
		token string
		// leeway
		leeway time.Duration
		// test result
		expectedErrorMsg string
	}{
		{
			name: "pass - token HS256",
			configuration: NewConfiguration(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			leeway:           jwt.DefaultLeeway,
			expectedErrorMsg: "",
		},
		{
			name: "pass - token ES384",
			configuration: NewConfiguration(
				defaultSecretProviderES384,
				defaultAudience,
				defaultIssuer,
				jose.ES384,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.ES384,
				defaultSecretES384,
			),
			leeway:           jwt.DefaultLeeway,
			expectedErrorMsg: "",
		},
		{
			name: "pass - token, config empty iss, aud",
			configuration: NewConfiguration(
				defaultSecretProvider,
				emptyAudience,
				emptyIssuer,
				jose.HS256,
			),
			token: getTestToken(
				emptyAudience,
				emptyIssuer,
				time.Now().Add(24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			leeway:           jwt.DefaultLeeway,
			expectedErrorMsg: "",
		},
		{
			name: "pass - token HS256 config no enforce sig alg",
			configuration: NewConfigurationTrustProvider(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			leeway:           jwt.DefaultLeeway,
			expectedErrorMsg: "",
		},
		{
			name: "pass - token ES384 config no enforce sig alg",
			configuration: NewConfigurationTrustProvider(
				defaultSecretProviderES384,
				defaultAudience,
				defaultIssuer,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.ES384,
				defaultSecretES384,
			),
			leeway:           jwt.DefaultLeeway,
			expectedErrorMsg: "",
		},
		{
			name: "pass - token not expired because of leeway",
			configuration: NewConfiguration(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(-1*time.Minute),
				jose.HS256,
				defaultSecret,
			),
			leeway:           2 * time.Minute,
			expectedErrorMsg: "",
		},
		{
			name: "fail - config no enforce sig alg but invalid token alg",
			configuration: NewConfigurationTrustProvider(
				defaultSecretProviderES384,
				defaultAudience,
				defaultIssuer,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.RS256,
				defaultSecretRS256,
			),
			leeway:           jwt.DefaultLeeway,
			expectedErrorMsg: "error in cryptographic primitive",
		},
		{
			name: "fail - invalid config secret provider",
			configuration: NewConfiguration(
				SecretProviderFunc(invalidProvider),
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			leeway:           jwt.DefaultLeeway,
			expectedErrorMsg: "invalid secret provider",
		},
		{
			name: "fail - invalid token aud",
			configuration: NewConfiguration(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				[]string{"invalid aud"},
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			leeway:           jwt.DefaultLeeway,
			expectedErrorMsg: "invalid audience claim (aud)",
		},
		{
			name: "fail - invalid token iss",
			configuration: NewConfiguration(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				defaultAudience,
				"invalid iss",
				time.Now().Add(24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			leeway:           jwt.DefaultLeeway,
			expectedErrorMsg: "invalid issuer claim (iss)",
		},
		{
			name: "fail - invalid token expiry",
			configuration: NewConfiguration(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(-24*time.Hour),
				jose.HS256,
				defaultSecret,
			),
			leeway:           jwt.DefaultLeeway,
			expectedErrorMsg: "token is expired (exp)",
		},
		{
			name: "fail - invalid token alg",
			configuration: NewConfiguration(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(-24*time.Hour),
				jose.HS384,
				defaultSecret,
			),
			leeway:           jwt.DefaultLeeway,
			expectedErrorMsg: "algorithm is invalid",
		},
		{
			name: "fail - invalid token secret",
			configuration: NewConfiguration(
				defaultSecretProvider,
				defaultAudience,
				defaultIssuer,
				jose.HS256,
			),
			token: getTestToken(
				defaultAudience,
				defaultIssuer,
				time.Now().Add(24*time.Hour),
				jose.HS256,
				[]byte("invalid secret"),
			),
			leeway:           jwt.DefaultLeeway,
			expectedErrorMsg: "error in cryptographic primitive",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator, req := genTestConfiguration(test.configuration, test.token)

			jwt, err := validator.ValidateRequestWithLeeway(req, test.leeway)

			if test.expectedErrorMsg != "" {
				if err == nil {
					t.Errorf("Validation should have failed with error with substring: " + test.expectedErrorMsg)
				} else if !strings.Contains(err.Error(), test.expectedErrorMsg) {
					t.Errorf("Validation should have failed with error with substring: " + test.expectedErrorMsg + ", but got: " + err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Validation should not have failed with error, but got: " + err.Error())
				}

				// claims should be unmarshalled successfully
				claims := map[string]interface{}{}
				err = validator.Claims(jwt, &claims)
				if err != nil {
					t.Errorf("Claims unmarshall should not have failed with error, but got: " + err.Error())
				}
			}
		})
	}
}
