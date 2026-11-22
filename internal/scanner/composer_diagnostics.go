package scanner

import (
	"strings"

	"vulman/internal/apperror"
)

// Classify bounded, private stderr into application-owned troubleshooting text.
// Never include package names, URLs, proxy values, tokens, or raw output.
func composerTransportError(stderr []byte) error {
	text := strings.ToLower(string(stderr))
	contains := func(patterns ...string) bool {
		for _, pattern := range patterns {
			if strings.Contains(text, pattern) {
				return true
			}
		}
		return false
	}

	switch {
	case contains("composer_disable_network", "network disabled", "network has been disabled"):
		return apperror.New("composer_network_disabled", "Composer networking is disabled. Check COMPOSER_DISABLE_NETWORK in Vulman's launch environment, then retry the scan.")
	case contains("curl error 5 ", "could not resolve proxy", "unable to use a proxy", "proxy authentication required", "407 proxy"):
		return apperror.New("composer_network_proxy", "Composer could not use the configured proxy. Check its proxy address, authentication, and network access, then retry the scan.")
	case contains("curl error 6 ", "could not resolve host", "getaddrinfo failed", "temporary failure in name resolution"):
		return apperror.New("composer_network_dns", "Composer could not resolve a package registry hostname. Check DNS, VPN, and proxy settings, then retry the scan.")
	case contains("curl error 60 ", "certificate verify failed", "ssl certificate problem", "unable to get local issuer certificate"):
		return apperror.New("composer_network_certificate", "Composer could not verify an HTTPS certificate. Check PHP/Composer's trusted CA certificates and any HTTPS-inspecting proxy. Keep certificate verification enabled.")
	case contains("curl error 35 ", "ssl connect error", "tls handshake"):
		return apperror.New("composer_network_tls", "Composer's HTTPS/TLS connection failed. Check PHP's TLS support and proxy configuration, then retry the scan. Keep certificate verification enabled.")
	case contains("rate limit", "too many requests", "http/2 429", "http/1.1 429", "http 429"):
		return apperror.New("composer_network_rate_limit", "A package registry rate-limited Composer. Wait before retrying the scan.")
	case contains("401 unauthorized", "403 forbidden", "http/2 401", "http/2 403", "http/1.1 401", "http/1.1 403", "http 401", "http 403", "authentication required", "invalid credentials"):
		return apperror.New("composer_network_access", "A package registry rejected Composer's access. Check Composer's package-registry credentials and permissions, then retry the scan.")
	case contains("curl error 28 ", "timed out", "operation timeout"):
		return apperror.New("composer_network_timeout", "Composer's package-registry request timed out. Check network, VPN, proxy, and firewall settings, then retry the scan.")
	case contains("curl error 7 ", "failed to connect", "could not connect"):
		return apperror.New("composer_network_connection", "Composer could not connect to a package registry or proxy. Check network access and proxy settings, then retry the scan.")
	default:
		return apperror.New("composer_network_failure", "Composer reported a network or HTTP failure (exit 100). Check package-registry availability, proxy settings, trusted CA certificates, and registry credentials, then retry the scan.")
	}
}
