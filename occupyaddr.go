package sockaddr

func IfByOccupy(ifAddrs IfAddrs, occupyNets SockAddrs) (matched, remainder IfAddrs) {
	if occupyNets == nil {
		return
	}

	for _, ifAddr := range ifAddrs {
		var contained bool
		for _, rfcNet := range occupyNets {
			if rfcNet.Contains(ifAddr.SockAddr) {
				matched = append(matched, ifAddr)
				contained = true
				break
			}
		}
		if !contained {
			remainder = append(remainder, ifAddr)
		}
	}
	return matched, remainder
}
