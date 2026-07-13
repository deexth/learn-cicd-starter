package auth

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	testCases := map[string]struct {
		input   string
		key     string
		wantErr string
	}{
		"Wrong Auth format": {
			input:   "Apikey Authkey",
			key:     "",
			wantErr: "malformed authorization header",
		},
		"No auth tail": {
			input:   "ApiKey",
			key:     "",
			wantErr: "malformed authorization header",
		},
		"No space in Auth": {
			input:   "ApiKeyAuthkey",
			key:     "",
			wantErr: "malformed authorization header",
		},
		"Correct Auth format": {
			input:   "ApiKey Authkey",
			key:     "Authkey",
			wantErr: "not expecting an error",
		},
	}
	header := &http.Header{}

	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			header.Set("Authorization", tt.input)
			got, err := GetAPIKey(*header)
			if err != nil {
				if strings.Contains(err.Error(), tt.wantErr) {
					return
				}
				t.Errorf("Unexpected: TestGetAPIKey: %v\n", err)
				return
			}
			if !reflect.DeepEqual(tt.key, got) {
				t.Fatalf("expected: %v, got: %v", tt.key, got)
			}
		})
	}
}
