package sockaddr_test

import (
	"testing"

	"github.com/hashicorp/go-sockaddr"
)

func TestExtendKnownRFCs(t *testing.T) {
	tests := []struct {
		name      string
		env       string
		sa        sockaddr.SockAddr
		rfcNum    uint
		result    bool
		wantPanic bool
	}{
		{
			name:   "rfc6890 extend pass",
			env:    "6890#172.240.0.0/16",
			sa:     sockaddr.MustIPv4Addr("172.240.0.0/16"),
			rfcNum: 6890,
			result: true,
		},
		{
			name:   "rfc6890 extend pass",
			env:    "6890#172.240.0.0/16,172.241.0.0/16",
			sa:     sockaddr.MustIPv4Addr("172.241.0.0/16"),
			rfcNum: 6890,
			result: true,
		},
		{
			name:      "invalid env 1",
			env:       "6890#172.240.0.0/16,",
			sa:        sockaddr.MustIPv4Addr("172.240.0.0/16"),
			rfcNum:    6890,
			result:    true,
			wantPanic: true,
		},
		{
			name:   "rfc6890 extend failed",
			env:    "999#172.240.0.0/16",
			sa:     sockaddr.MustIPv4Addr("172.240.0.0/16"),
			rfcNum: 6890,
			result: false,
		},
		{
			name:      "invalid env 2",
			env:       "6890:172.240.0.0/16",
			sa:        sockaddr.MustIPv4Addr("172.240.0.0/16"),
			rfcNum:    6890,
			result:    false,
			wantPanic: true,
		},
	}

	for i, test := range tests {
		t.Setenv("RFCS_EXTENDING_ENV", test.env)
		if test.name == "" {
			t.Fatalf("test %d needs a name", i)
		}

		if test.wantPanic {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("function should panic")
				}
			}()
		}
		result := sockaddr.IsRFC(test.rfcNum, test.sa)
		if result != test.result {
			t.Fatalf("expected a match")
		}
	}
}
