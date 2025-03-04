package gojwttoken

import (
	b64 "encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"time"
)

// Struct describing a jwt token.
type jwtToken struct {
	Typ         string `json:"typ"`
	Alg         string `json:"alg"`
	Iss         string `json:"iss"`
	Exp         int64  `json:"exp"`
	Iat         int64  `json:"iat"`
	Jti         string `json:"jti"`
	AccessKeyId string `json:"accessKeyId"`
}

// Validate jwt token. If token not valid stop execution.
// https://tools.ietf.org/html/rfc7519
func ValidateJwtToken(token string) bool {
	// Check if tokens contains a "." or starts with "eyJ".
	if !strings.Contains(token, ".") || !strings.HasPrefix(token, "eyJ") {
		log.Fatal("Provided token does not contain '.' or starts with 'eyj'.")
	}

	i := 0
	for i < 2 {
		// Split token into parts and return token on position i.
		Token := strings.Split(token, ".")[i]
		// Replace all "-" with "+" and "_" with "/".
		Token = strings.Replace(strings.Replace(Token, "-", "+", -1), "_", "/", -1)
		switch len(Token) % 4 {
		case 2:
			Token += "=="
		case 3:
			Token += "="
		}
		// Advance by 1.
		i++
	}
	// Return true if token is valid.
	return true
}

// Get jwt token payload infos.
func GetJwtTokenPayloadInfos(token string) jwtToken {
	var jwtTok jwtToken

	// Extract payload information.
	TokenPayLoad := strings.Split(token, ".")[1]
	TokenPayLoad = strings.Replace(strings.Replace(TokenPayLoad, "-", "+", -1), "_", "/", -1)
	// Decode b64 string.
	sDecPayload, err := b64.StdEncoding.DecodeString(TokenPayLoad)

	if err != nil {
		panic(err)
	}

	// Unmarshal json result and safe to struct.
	e := json.Unmarshal(sDecPayload, &jwtTok)

	if e != nil {
		panic(e)
	}

	return jwtTok
}

// Get jwt token header infos.
func GetJwtTokenHeaderInfos(token string) jwtToken {
	var jwtTok jwtToken

	TokenHeader := strings.Split(token, ".")[0]
	TokenHeader = strings.Replace(strings.Replace(TokenHeader, "-", "+", -1), "_", "/", -1)

	sDecHeader, err := b64.StdEncoding.DecodeString(TokenHeader)

	if err != nil {
		panic(err)
	}

	e := json.Unmarshal(sDecHeader, &jwtTok)

	if e != nil {
		panic(e)
	}

	return jwtTok
}

// Get token lifetime.
func GetJwtTokenLifeTime(token string) time.Duration {
	var timeUntilExpiry time.Duration
	var jwtTok jwtToken

	TokenPayLoad := strings.Split(token, ".")[1]
	TokenPayLoad = strings.Replace(strings.Replace(TokenPayLoad, "-", "+", -1), "_", "/", -1)

	sDecPayload, err := b64.StdEncoding.DecodeString(TokenPayLoad)

	if err != nil {
		log.Fatal(err)
	}
	e := json.Unmarshal(sDecPayload, &jwtTok)

	if e != nil {
		panic(e)
	}
	// Get current time.
	now := time.Now()
	// Convert jwt time to unix time.
	unixTime := time.Unix(jwtTok.Exp, 0)
	// Calculate difference between jwt time and now.
	timeUntilExpiry = now.Sub(unixTime)
	// Check if time is left if not raise error.
	if timeUntilExpiry.Minutes() > 0 {
		log.Fatal("Token is expired.")
	}

	return timeUntilExpiry
}
