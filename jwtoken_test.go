package gojwtoken

import (
	"os"
	"reflect"
	"testing"
	"time"
)

var testdir = "examples/jwtoken.txt"

// Test if the provided token is valid.
func TestValidateJwToken(t *testing.T) {
	// Open and read file.
	dat, err := os.ReadFile(testdir)
	// Catch error.
	if err != nil {
		panic(err)
	}

	res := ValidateJwToken(string(dat))
	// Parse content of file to function.
	if res != true {
		t.Errorf("Expected %v got %v", true, res)
	}
}

// Test if result of function is of type jwToken.
func TestGetJwTokenPayloadInfos(t *testing.T) {
	var jtok jwToken

	// Open and read file.
	dat, err := os.ReadFile(testdir)
	// Catch error.
	if err != nil {
		panic(err)
	}

	res := GetJwTokenPayloadInfos(string(dat))
	if reflect.TypeOf(res) != reflect.TypeOf(jtok) {
		t.Errorf("Expected type %T got %T:", jtok, res)
	}
}

// Test if result of function is of type jwToken.
func TestGetJwTokenHeaderInfos(t *testing.T) {
	var jtok jwToken

	// Open and read file.
	dat, err := os.ReadFile(testdir)
	// Catch error.
	if err != nil {
		panic(err)
	}

	res := GetJwTokenHeaderInfos(string(dat))
	if reflect.TypeOf(res) != reflect.TypeOf(jtok) {
		t.Errorf("Expected type %T got %T:", jtok, res)
	}
}

// Test if result is of type string because you can not test for test.Duration.
func TestGetJwtTokenLifeTime(t *testing.T) {

	// Open and read file.
	dat, err := os.ReadFile(testdir)
	// Catch error.
	if err != nil {
		panic(err)
	}

	res := GetJwtTokenLifeTime(string(dat))

	if reflect.TypeOf(res.String()) != reflect.TypeOf(time.Duration.String(res)) {
		t.Errorf("Expected type %T got %T:", time.Duration.String(res), res.String())
	}
}
