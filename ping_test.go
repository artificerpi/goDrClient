package main

import (
	"testing"
)

func TestCheckNTP(t *testing.T) {
	if !checkNTP() {
		t.Error("Not available!")
	}
}
