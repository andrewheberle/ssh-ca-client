package certfile

import "github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"

var _ cert.Requestable = &UserCertificate{}
var _ cert.Renewable = &HostCertificate{}

type UserCertificate struct {
}

func (c *UserCertificate) Request() error {
	return nil
}

type HostCertificate struct {
}

func (c *HostCertificate) Request() error {
	return nil
}

func (c *HostCertificate) Renew() error {
	return nil
}
