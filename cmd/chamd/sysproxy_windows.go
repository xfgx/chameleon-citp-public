//go:build windows

package main

// Автоподхват через системный прокси Windows (fallback, если TUN
// недоступен, например нет прав администратора). Браузеры и большинство
// приложений подхватывают SOCKS5 сами.

func SetSystemProxy(enable bool, socksAddr string) error {
	key := `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	if enable {
		if err := run("reg", "add", key, "/v", "ProxyServer", "/t", "REG_SZ", "/d", "socks="+socksAddr, "/f"); err != nil {
			return err
		}
		if err := run("reg", "add", key, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "<local>", "/f"); err != nil {
			return err
		}
		return run("reg", "add", key, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f")
	}
	return run("reg", "add", key, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f")
}
