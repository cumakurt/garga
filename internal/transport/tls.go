package transport

import (
	"crypto/tls"
	"time"
)

// TLSInfo is bounded connection metadata. It intentionally omits raw certificates.
type TLSInfo struct {
	Version     uint16
	CipherSuite uint16
	ServerName  string
	Verified    bool
	Certificate *CertificateInfo
}

// CertificateInfo contains only the leaf fields needed for health reporting.
type CertificateInfo struct {
	Subject       string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	HostnameValid bool
	SelfSigned    bool
}

func connectionTLSInfo(state *tls.ConnectionState, hostname string) *TLSInfo {
	if state == nil {
		return nil
	}
	info := &TLSInfo{
		Version:     state.Version,
		CipherSuite: state.CipherSuite,
		ServerName:  state.ServerName,
		Verified:    len(state.VerifiedChains) > 0,
	}
	if len(state.PeerCertificates) == 0 {
		return info
	}
	leaf := state.PeerCertificates[0]
	info.Certificate = &CertificateInfo{
		Subject:       leaf.Subject.String(),
		Issuer:        leaf.Issuer.String(),
		NotBefore:     leaf.NotBefore,
		NotAfter:      leaf.NotAfter,
		HostnameValid: leaf.VerifyHostname(hostname) == nil,
		SelfSigned:    leaf.RawSubject != nil && string(leaf.RawSubject) == string(leaf.RawIssuer) && leaf.CheckSignatureFrom(leaf) == nil,
	}
	return info
}
