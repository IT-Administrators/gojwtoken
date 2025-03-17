package gojwtoken

import (
	b64 "encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"time"
)

// A jwt token with this leading base64 encoded string uses no encryption algorithm.
const unsecureTokenB64 = "eyJhbGciOiJub25lIn0"

// Struct describing a jwt token.
type jwToken struct {
	Typ string `json:"typ"` // Type: string
	Cty string `json:"cty"` // Content type
	Alg string `json:"alg"` // Encryption algorithm: string
	Iss string `json:"iss"` // Issuer: string
	Exp int64  `json:"exp"` // Expiration time: int
	Iat int64  `json:"iat"` // Issued at: int
	Jti string `json:"jti"` // JWT ID: string
	Sub string `json:"sub"` // Subject: string
	Aud string `json:"aud"` // Audience: string
	Nbf int    `json:"nbf"` // Not before: int
}

// Validate jwt token. If token not valid stop execution.
// https://tools.ietf.org/html/rfc7519
func ValidateJwToken(token string) bool {
	// Check if tokens contains a "." or starts with "eyJ".
	if !strings.Contains(token, ".") || !strings.HasPrefix(token, "eyJ") {
		log.Fatal("Provided token does not contain '.' or starts with 'eyJ'.")
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
func GetJwTokenPayloadInfos(token string) jwToken {
	var jwtTok jwToken

	// Extract payload information.
	TokenPayLoad := strings.Split(token, ".")[1]
	TokenPayLoad = strings.Replace(strings.Replace(TokenPayLoad, "-", "+", -1), "_", "/", -1)

	// Decode b64 string.
	sDecPayload, err := b64.StdEncoding.DecodeString(TokenPayLoad)
	if err != nil {
		log.Fatal(err)
	}

	// Unmarshal json result and safe to struct.
	e := json.Unmarshal(sDecPayload, &jwtTok)

	if e != nil {
		log.Fatal(e)
	}

	return jwtTok
}

// Get jwt token header infos.
func GetJwTokenHeaderInfos(token string) jwToken {
	var jwtTok jwToken

	// Extract header information.
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
func GetJwTokenLifeTime(token string) time.Duration {
	var timeUntilExpiry time.Duration
	var jwtTok jwToken

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

	// Calculate time that is elapsed since token retrieval.
	// timeUntilExpiry = time.Now().Sub(time.Unix(jwtTok.Exp, 0))
	// Go recommends using time.Since for duration calculation.
	timeUntilExpiry = time.Since(time.Unix(jwtTok.Exp, 0))
	// Check if time is left, if not raise error.
	if timeUntilExpiry.Minutes() > 0 {
		log.Fatal("Token is expired.")
	}

	return timeUntilExpiry
}

// Check if token is unsecure.
func IsUnsecuredJwToken(token string) bool {
	return strings.Contains(token, unsecureTokenB64)
}
