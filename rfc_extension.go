package sockaddr

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const RfcsExtendEnv = "RFCS_EXTENDING_ENV"

// ExtendKnownRFCs Extend the RFCs with Environments
func ExtendKnownRFCs(addrs map[uint]SockAddrs) map[uint]SockAddrs {
	env := os.Getenv(RfcsExtendEnv)
	if len(env) == 0 {
		return addrs
	}

	extends := readExtensions(env)
	for rfc, sockAddrs := range extends {
		if value, exists := addrs[rfc]; exists {
			addrs[rfc] = append(value, sockAddrs...)
		}
	}
	return addrs
}

// 6890#172.240.0.0/16,;
func readExtensions(env string) map[uint]SockAddrs {
	result := map[uint]SockAddrs{}
	rfcs := strings.Split(env, ";")
	for _, rfcExtend := range rfcs {
		if ok, rfc, addrs := buildSockAddrs(rfcExtend); ok {
			result[rfc] = addrs
		}
	}
	return result
}

func buildSockAddrs(rfcExtend string) (bool, uint, SockAddrs) {
	if len(rfcExtend) == 0 {
		return false, 0, nil
	}
	sections := strings.Split(rfcExtend, "#")
	if len(sections) != 2 {
		panic(fmt.Sprintf("Invalid env to entending rfcs, value: %v, should be 'number#ip_range'.", rfcExtend))
	}
	rfc, err := strconv.ParseUint(sections[0], 10, 32)
	if err != nil {
		return false, 0, nil
	}

	ranges := strings.Split(sections[1], ",")
	if len(ranges) < 1 {
		return false, 0, nil
	}

	addrs := SockAddrs{}
	for _, r := range ranges {
		addrs = append(addrs, MustIPAddr(r))
	}
	return true, uint(rfc), addrs
}
