package auth0

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestFromRequestHeaderExtraction(t *testing.T) {
	referenceToken := getTestToken(defaultAudience, defaultIssuer, time.Now(), jose.HS256, defaultSecret)

	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	headerValue := fmt.Sprintf("Bearer %s", referenceToken)
	headerTokenRequest.Header.Add("Authorization", headerValue)

	token, err := FromHeader(headerTokenRequest)
	if err != nil {
		t.Error(err)
		return
	}

	claims := jwt.Claims{}
	err = token.Claims([]byte("secret"), &claims)
	if err != nil {
		t.Errorf("Claims should be decoded correctly with default token: %q \n", err)
		t.FailNow()
	}

	if claims.Issuer != defaultIssuer || !reflect.DeepEqual(claims.Audience, jwt.Audience(defaultAudience)) {
		t.Error("Invalid issuer, audience or subject:", claims.Issuer, claims.Audience)
	}
}

func TestFromRequestParamsExtraction(t *testing.T) {
	referenceToken := getTestToken(defaultAudience, defaultIssuer, time.Now(), jose.HS256, defaultSecret)

	paramTokenRequest, _ := http.NewRequest("", "http://localhost?token="+referenceToken, nil)

	token, err := FromParams(paramTokenRequest)
	if err != nil {
		t.Error(err)
		return
	}

	claims := jwt.Claims{}
	err = token.Claims([]byte("secret"), &claims)
	if err != nil {
		t.Errorf("Claims should be decoded correctly with default token: %q \n", err)
		t.FailNow()
	}

	if claims.Issuer != defaultIssuer || !reflect.DeepEqual(claims.Audience, jwt.Audience(defaultAudience)) {
		t.Error("Invalid issuer, audience or subject:", claims.Issuer, claims.Audience)
	}
}

func TestFromCookieExtraction(t *testing.T) {
	referenceToken := getTestToken(defaultAudience, defaultIssuer, time.Now(), jose.HS256, defaultSecret)

	cookieTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	cookieTokenRequest.AddCookie(&http.Cookie{Name: "access_token", Value: referenceToken})

	token, err := FromCookie(cookieTokenRequest)
	if err != nil {
		t.Error(err)
		return
	}

	claims := jwt.Claims{}
	err = token.Claims([]byte("secret"), &claims)
	if err != nil {
		t.Errorf("Claims should be decoded correctly with default token: %q \n", err)
		t.FailNow()
	}

	if claims.Issuer != defaultIssuer || !reflect.DeepEqual(claims.Audience, jwt.Audience(defaultAudience)) {
		t.Error("Invalid issuer, audience or subject:", claims.Issuer, claims.Audience)
	}
}

func TestFromMultipleExtraction(t *testing.T) {
	extractor := FromMultiple(RequestTokenExtractorFunc(FromHeader), RequestTokenExtractorFunc(FromParams), RequestTokenExtractorFunc(FromCookie))

	referenceToken := getTestToken(defaultAudience, defaultIssuer, time.Now(), jose.HS256, defaultSecret)
	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	headerValue := fmt.Sprintf("Bearer %s", referenceToken)
	headerTokenRequest.Header.Add("Authorization", headerValue)
	paramTokenRequest, _ := http.NewRequest("", "http://localhost?token="+referenceToken, nil)
	brokenParamTokenRequest, _ := http.NewRequest("", "http://localhost?token=broken", nil)
	cookieTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	cookieTokenRequest.AddCookie(&http.Cookie{Name: "access_token", Value: referenceToken})

	for _, r := range []*http.Request{headerTokenRequest, paramTokenRequest, brokenParamTokenRequest, cookieTokenRequest} {
		token, err := extractor.Extract(r)
		if err != nil {
			if r == brokenParamTokenRequest && err.Error() == "square/go-jose: compact JWS format must have three parts" {
				// Checking that the JWT error is returned.
				continue
			}
			t.Error(err)
			return
		}

		claims := jwt.Claims{}
		err = token.Claims([]byte("secret"), &claims)
		if err != nil {
			t.Errorf("Claims should be decoded correctly with default token: %q \n", err)
			t.FailNow()
		}

		if claims.Issuer != defaultIssuer || !reflect.DeepEqual(claims.Audience, jwt.Audience(defaultAudience)) {
			t.Error("Invalid issuer, audience or subject:", claims.Issuer, claims.Audience)
		}
	}
}

func TestInvalidExtract(t *testing.T) {
	headerTokenRequest, _ := http.NewRequest("", "http://localhost", nil)
	_, err := FromHeader(headerTokenRequest)

	if err == nil {
		t.Error("A request without valid Authorization header should return an error.")
	}
}

func TestFromHeader(t *testing.T) {
	tReq := httptest.NewRequest("", "https://", nil)
	referenceToken := getTestToken(defaultAudience, defaultIssuer, time.Now(), jose.HS256, defaultSecret)
	headerValue := fmt.Sprintf("Bearer %s", referenceToken)
	tReq.Header.Add("Authorization", headerValue)

	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid request", args{tReq}, false},
		{"nil request", args{nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FromHeader(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestFromParams(t *testing.T) {
	referenceToken := getTestToken(defaultAudience, defaultIssuer, time.Now(), jose.HS256, defaultSecret)
	tReq := httptest.NewRequest("", "http://example.com?token="+referenceToken, nil)

	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid request", args{tReq}, false},
		{"nil request", args{nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FromParams(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
