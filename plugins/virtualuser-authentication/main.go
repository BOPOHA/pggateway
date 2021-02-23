package virtualuser_authentication

// https://www.postgresql.org/docs/11/protocol-flow.html
// https://www.postgresql.org/docs/11/sasl-authentication.html
// https://www.postgresql.org/docs/11/protocol-message-formats.html

import (
	"fmt"
	"github.com/c653labs/pggateway"
	"github.com/c653labs/pgproto"
)

type VirtualUserCredentials map[string]string
type VirtualUserAuth struct {
	virtualCredentials VirtualUserCredentials
	dbUser             string
	dbPassword         string
	dbSSL              bool
}

func init() {
	pggateway.RegisterAuthPlugin("virtualuser-authentication", newVirtualUserPlugin)
}

func newVirtualUserPlugin(config pggateway.ConfigMap) (pggateway.AuthenticationPlugin, error) {
	var ok bool
	auth := &VirtualUserAuth{virtualCredentials: make(VirtualUserCredentials)}

	virtualCredentials, ok := config.Map("virtualusers")
	if !ok {
		return nil, fmt.Errorf("'virtualusers' is required")
	}
	for k, v := range virtualCredentials {
		value, ok := v.(string)
		if !ok {
			continue
		}
		auth.virtualCredentials[k] = value
	}

	db, ok := config.Map("db")
	if !ok {
		return nil, fmt.Errorf("'db' configuration value is required")
	}

	auth.dbUser, ok = db.String("user")
	if !ok {
		return nil, fmt.Errorf("'db.user' configuration value is required")
	}
	auth.dbPassword = db.StringDefault("password", "")
	auth.dbSSL = db.BoolDefault("ssl", true)

	return auth, nil
}

func (p *VirtualUserAuth) Authenticate(sess *pggateway.Session, startup *pgproto.StartupMessage) (bool, error) {

	err := p.AuthenticateClient(sess)
	if err != nil {
		return false, err
	}
	err = p.AuthOnServer(sess, startup)
	if err != nil {
		return false, err
	}
	return true, nil
}
