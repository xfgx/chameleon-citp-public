
// privateDNS — приватные IPv4 DNS-серверы машины: DNS домашнего роутера надо
// оставить снаружи туннеля (его /32 через физический шлюз), иначе резолв умрёт.
func privateDNS() []string {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses").Output()
	if err != nil {
		return nil
	}
	var res []string
	seen := map[string]bool{}
	for _, ln := range strings.Split(string(out), "\n") {
		s := strings.TrimSpace(ln)
		ip := net.ParseIP(s)
		if ip == nil || !isPrivate(ip) || seen[s] {
			continue
		}
		seen[s] = true
		res = append(res, s)
	}
	return res
}

func isPrivate(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	switch {
	case v4[0] == 10, v4[0] == 192 && v4[1] == 168, v4[0] == 169 && v4[1] == 254:
		return true
	case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
		return true
	}
	return false
}
