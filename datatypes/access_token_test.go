package datatypes

import (
	"log"
	"testing"
)

func TestAccessToken(t *testing.T) {
	// All claims have been replaced with fake values,
	// and the header and sig parts are removed.
	// Don't attempt to use this token
	fakeToken := ".eyJhdWQiOiJGVUNLIiwiZGlkIjoiQ0FOMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJleHAiOjI5OTk5OTk5OTksImhpZCI6IjAwMDAwMDAwMDAwMDAwMDAiLCJpYXQiOjE1OTk5OTk5OTksImlzcyI6Imp3dC1zZXJ2aWNlIiwianRpIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwibG9jIjoiZW4iLCJuYmYiOjE5OTk5OTk5OTksInJlZyI6IjIwNDAtMDEtMDFUMDA6MDA6MDBaIiwic3ViIjoia2lrdGVhbSIsInRwZSI6InIiLCJ2ZXIiOiIxNy4wLjAtMDAwMDAifQ."
	accessToken := ParseAccessToken(fakeToken)
	if accessToken == nil {
		t.Error("failed to parse token")
		return
	}
	log.Printf("%+v\n", accessToken)
}
