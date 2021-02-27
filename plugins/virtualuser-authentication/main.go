package virtualuser_authentication

// https://www.postgresql.org/docs/11/protocol-flow.html
// https://www.postgresql.org/docs/11/sasl-authentication.html
// https://www.postgresql.org/docs/11/protocol-message-formats.html

import (
	"github.com/c653labs/pggateway"
)

type VirtualUserCredentials map[string]string
type VirtualUserAuth struct {
	virtualCredentials VirtualUserCredentials
}

func init() {
	pggateway.RegisterAuthPlugin("virtualuser-authentication", newVirtualUserPlugin)
}

func newVirtualUserPlugin(config pggateway.ConfigMap) (pggateway.AuthenticationPlugin, error) {
	auth := &VirtualUserAuth{virtualCredentials: make(VirtualUserCredentials)}
	return auth, nil
}

func (p *VirtualUserAuth) Authenticate(sess *pggateway.Session) (bool, error) {

	err := p.AuthenticateClient(sess)
	if err != nil {
		return false, err
	}

	return true, nil
}
