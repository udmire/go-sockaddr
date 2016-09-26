package sockaddr_test

import (
	"testing"

	"github.com/hashicorp/go-sockaddr"
)

func TestSockAddr_New(t *testing.T) {
	type SockAddrFixture struct {
		input              string
		ResultType         string
		NetworkAddress     string
		BroadcastAddress   string
		IPUint32           sockaddr.IPv4Address
		Maskbits           int
		BinString          string
		HexString          string
		FirstUsableAddress string
		LastUsableAddress  string
	}
	type SockAddrFixtures []SockAddrFixtures

	goodResults := []SockAddrFixture{
		{
			input:              "0.0.0.0",
			ResultType:         "ipv4",
			NetworkAddress:     "0.0.0.0",
			BroadcastAddress:   "0.0.0.0",
			Maskbits:           32,
			IPUint32:           0,
			BinString:          "00000000000000000000000000000000",
			HexString:          "00000000",
			FirstUsableAddress: "0.0.0.0",
			LastUsableAddress:  "0.0.0.0",
		},
		{
			input:              "0.0.0.0/0",
			ResultType:         "ipv4",
			NetworkAddress:     "0.0.0.0",
			BroadcastAddress:   "255.255.255.255",
			Maskbits:           0,
			IPUint32:           0,
			BinString:          "00000000000000000000000000000000",
			HexString:          "00000000",
			FirstUsableAddress: "0.0.0.1",
			LastUsableAddress:  "255.255.255.254",
		},
		{
			input:              "0.0.0.1",
			ResultType:         "ipv4",
			NetworkAddress:     "0.0.0.1",
			BroadcastAddress:   "0.0.0.1",
			Maskbits:           32,
			IPUint32:           1,
			BinString:          "00000000000000000000000000000001",
			HexString:          "00000001",
			FirstUsableAddress: "0.0.0.1",
			LastUsableAddress:  "0.0.0.1",
		},
		{
			input:              "0.0.0.1/1",
			ResultType:         "ipv4",
			NetworkAddress:     "0.0.0.0",
			BroadcastAddress:   "127.255.255.255",
			Maskbits:           1,
			IPUint32:           1,
			BinString:          "00000000000000000000000000000001",
			HexString:          "00000001",
			FirstUsableAddress: "0.0.0.1",
			LastUsableAddress:  "127.255.255.254",
		},
		{
			input:              "128.0.0.0",
			ResultType:         "ipv4",
			NetworkAddress:     "128.0.0.0",
			BroadcastAddress:   "128.0.0.0",
			Maskbits:           32,
			IPUint32:           2147483648,
			BinString:          "10000000000000000000000000000000",
			HexString:          "80000000",
			FirstUsableAddress: "128.0.0.0",
			LastUsableAddress:  "128.0.0.0",
		},
		{
			input:              "255.255.255.255",
			ResultType:         "ipv4",
			NetworkAddress:     "255.255.255.255",
			BroadcastAddress:   "255.255.255.255",
			Maskbits:           32,
			IPUint32:           4294967295,
			BinString:          "11111111111111111111111111111111",
			HexString:          "ffffffff",
			FirstUsableAddress: "255.255.255.255",
			LastUsableAddress:  "255.255.255.255",
		},
		{
			input:              "1.2.3.4",
			ResultType:         "ipv4",
			NetworkAddress:     "1.2.3.4",
			BroadcastAddress:   "1.2.3.4",
			Maskbits:           32,
			IPUint32:           16909060,
			BinString:          "00000001000000100000001100000100",
			HexString:          "01020304",
			FirstUsableAddress: "1.2.3.4",
			LastUsableAddress:  "1.2.3.4",
		},
		{
			input:              "192.168.10.10/16",
			ResultType:         "ipv4",
			NetworkAddress:     "192.168.0.0",
			BroadcastAddress:   "192.168.255.255",
			Maskbits:           16,
			IPUint32:           3232238090,
			BinString:          "11000000101010000000101000001010",
			HexString:          "c0a80a0a",
			FirstUsableAddress: "192.168.0.1",
			LastUsableAddress:  "192.168.255.254",
		},
		{
			input:              "192.168.1.10/24",
			ResultType:         "ipv4",
			NetworkAddress:     "192.168.1.0",
			BroadcastAddress:   "192.168.1.255",
			Maskbits:           24,
			IPUint32:           3232235786,
			BinString:          "11000000101010000000000100001010",
			HexString:          "c0a8010a",
			FirstUsableAddress: "192.168.1.1",
			LastUsableAddress:  "192.168.1.254",
		},
		{
			input:              "192.168.0.1",
			ResultType:         "ipv4",
			NetworkAddress:     "192.168.0.1",
			BroadcastAddress:   "192.168.0.1",
			Maskbits:           32,
			IPUint32:           3232235521,
			BinString:          "11000000101010000000000000000001",
			HexString:          "c0a80001",
			FirstUsableAddress: "192.168.0.1",
			LastUsableAddress:  "192.168.0.1",
		},
		{
			input:              "192.168.0.2/31",
			ResultType:         "ipv4",
			NetworkAddress:     "192.168.0.2",
			BroadcastAddress:   "192.168.0.3",
			Maskbits:           31,
			IPUint32:           3232235522,
			BinString:          "11000000101010000000000000000010",
			HexString:          "c0a80002",
			FirstUsableAddress: "192.168.0.2",
			LastUsableAddress:  "192.168.0.3",
		},
		{
			input:              "240.0.0.0/4",
			ResultType:         "ipv4",
			NetworkAddress:     "240.0.0.0",
			BroadcastAddress:   "255.255.255.255",
			Maskbits:           4,
			IPUint32:           4026531840,
			BinString:          "11110000000000000000000000000000",
			HexString:          "f0000000",
			FirstUsableAddress: "240.0.0.1",
			LastUsableAddress:  "255.255.255.254",
		},
	}

	for idx, r := range goodResults {
		var (
			addr sockaddr.IPAddr
			str  string
		)

		sa, err := sockaddr.NewSockAddr(r.input)
		if err != nil {
			t.Fatalf("Failed parse %s", r.input)
		}

		switch r.ResultType {
		case "ipv4":
			ipv4b, err := sockaddr.NewIPv4Addr(r.input)
			if err != nil {
				t.Fatalf("[%d] Unable to construct a new IPv4 from %s: %s", idx, r.input, err)
			}
			if !ipv4b.Equal(sa) {
				t.Fatalf("[%d] Equality comparison failed on fresh IPv4", idx)
			}

			type_ := sa.Type()
			if type_ != sockaddr.TypeIPv4 {
				t.Fatalf("[%d] Type mismatch for %s: %d", idx, r.input, type_)
			}

			ipv4 := sockaddr.ToIPv4Addr(sa)
			if ipv4 == nil {
				t.Fatalf("[%d] Failed ToIPv4Addr() %s", idx, r.input)
			}

			addr = ipv4.Broadcast()
			if addr == nil || addr.NetIP().To4().String() != r.BroadcastAddress {
				t.Fatalf("Failed IPv4Addr.BroadcastAddress() %s: expected %+q, received %+q", r.input, r.BroadcastAddress, addr.NetIP().To4().String())
			}

			maskbits := ipv4.Maskbits()
			if maskbits != r.Maskbits {
				t.Fatalf("Failed Maskbits %s: %d != %d", r.input, maskbits, r.Maskbits)
			}

			if ipv4.Address != r.IPUint32 {
				t.Fatalf("Failed ToUint32() %s: %d != %d", r.input, ipv4.Address, r.IPUint32)
			}

			str = ipv4.AddressBinString()
			if str != r.BinString {
				t.Fatalf("Failed BinString %s: %s != %s", r.input, str, r.BinString)
			}

			str = ipv4.AddressHexString()
			if str != r.HexString {
				t.Fatalf("Failed HexString %s: %s != %s", r.input, str, r.HexString)
			}

			addr = ipv4.Network()
			if addr == nil || addr.NetIP().To4().String() != r.NetworkAddress {
				t.Fatalf("Failed NetworkAddress %s: %s != %s", r.input, addr.NetIP().To4().String(), r.NetworkAddress)
			}

			addr = ipv4.FirstUsable()
			if addr == nil || addr.NetIP().To4().String() != r.FirstUsableAddress {
				t.Fatalf("Failed FirstUsableAddress %s: %s != %s", r.input, addr.NetIP().To4().String(), r.FirstUsableAddress)
			}

			addr = ipv4.LastUsable()
			if addr == nil || addr.NetIP().To4().String() != r.LastUsableAddress {
				t.Fatalf("Failed LastUsableAddress %s: %s != %s", r.input, addr.NetIP().To4().String(), r.LastUsableAddress)
			}
		default:
			t.Fatalf("Unknown result type: %s", r.ResultType)
		}
	}

	badResults := []string{
		"256.0.0.0",
		"0.0.0.0.0",
	}

	for _, badIP := range badResults {
		sa, err := sockaddr.NewSockAddr(badIP)
		if err == nil {
			t.Fatalf("Failed should have failed to parse %s: %v", badIP, sa)
		}
		if sa != nil {
			t.Fatalf("SockAddr should be nil")
		}
	}
}