package gojwttoken

import (
	"os"
	"reflect"
	"testing"
)

var testdir = "examples/jwttoken.txt"

// Test if the provided token is valid.
func TestValidateJWTToken(t *testing.T) {
	// Open and read file.
	dat, err := os.ReadFile(testdir)
	// Catch error.
	if err != nil {
		panic(err)
	}
	res := ValidateJwtToken(string(dat))
	// Parse content of file to function.
	if res != true {
		t.Errorf("Expected %v got %v", true, res)
	}
}

// Test if result of function is of type jwtToken.
func TestGetJwtTokenPayloadInfos(t *testing.T) {
	var jtok jwtToken

	// Open and read file.
	dat, err := os.ReadFile(testdir)
	// Catch error.
	if err != nil {
		panic(err)
	}
	res := GetJwtTokenPayloadInfos(string(dat))
	if reflect.TypeOf(res) != reflect.TypeOf(jtok) {
		t.Errorf("Expected type %T got %T:", jtok, res)
	}
}

// Test if result of function is of type jwtToken.
func TestGetJwtTokenHeaderInfos(t *testing.T) {
	var jtok jwtToken

	// Open and read file.
	dat, err := os.ReadFile(testdir)
	// Catch error.
	if err != nil {
		panic(err)
	}
	res := GetJwtTokenHeaderInfos(string(dat))
	if reflect.TypeOf(res) != reflect.TypeOf(jtok) {
		t.Errorf("Expected type %T got %T:", jtok, res)
	}
}
