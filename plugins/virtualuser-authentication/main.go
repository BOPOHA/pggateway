package virtualuser_authentication

// https://www.postgresql.org/docs/11/protocol-flow.html
// https://www.postgresql.org/docs/11/sasl-authentication.html
// https://www.postgresql.org/docs/11/protocol-message-formats.html

import (
	"github.com/c653labs/pggateway"
	"github.com/c653labs/pgproto"
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

	for k, v := range config {
		value, ok := v.(string)
		if !ok {
			continue
		}
		auth.virtualCredentials[k] = value
	}

	return auth, nil
}

func (p *VirtualUserAuth) Authenticate(sess *pggateway.Session, startup *pgproto.StartupMessage) (bool, error) {

	err := p.AuthenticateClient(sess)
	if err != nil {
		return false, err
	}

	return true, nil
}
