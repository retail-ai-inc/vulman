package scanner

import "testing"

func TestLinuxScannerPlatform(t *testing.T) {
	for _, tc := range []struct{ release, want string }{
		{"ID=ubuntu", "debian"},
		{"ID=linuxmint\nID_LIKE=\"ubuntu debian\"", "debian"},
		{"ID=rocky\nID_LIKE=\"rhel centos fedora\"", "fedora"},
		{"ID=endeavouros\nID_LIKE=arch", "arch"},
		{"ID=alpine", "alpine"},
		{"ID=unknown", "linux"},
	} {
		if got := linuxScannerPlatform(tc.release); got != tc.want {
			t.Errorf("platform for %q = %q, want %q", tc.release, got, tc.want)
		}
	}
}
