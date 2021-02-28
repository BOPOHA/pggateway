package virtualuser_authentication

// https://www.postgresql.org/docs/11/protocol-flow.html
// https://www.postgresql.org/docs/11/sasl-authentication.html
// https://www.postgresql.org/docs/11/protocol-message-formats.html

import (
	"github.com/c653labs/pggateway"
)

// VirtualuserAuthentication
type VirtualuserAuthentication struct {
	Name   string                 `json:"name"`
	Target pggateway.TargetConfig `json:"target"`
	Users  map[string]string      `json:"users"`
	//Logging Logging           `json:"logging"`
}

func init() {
	pggateway.RegisterAuthPlugin("virtualuser-authentication", newVirtualUserPlugin)
}

func newVirtualUserPlugin(config pggateway.ConfigMap) (plugin pggateway.AuthenticationPlugin, err error) {
	plugin = &VirtualuserAuthentication{}
	err = pggateway.FillStruct(config, plugin)
	//fmt.Printf("%#v\n%#v\n%v\n", plugin, config, err)
	return
}

func (p *VirtualuserAuthentication) Authenticate(sess *pggateway.Session) (bool, error) {

	err := p.AuthenticateClient(sess)
	if err != nil {
		return false, err
	}
	err = sess.DialToS(p.Target.Host, p.Target.Port)
	if err != nil {
		return false, err
	}
	err = sess.AuthOnServer(p.Target.User, p.Target.Password)
	if err != nil {
		return false, err
	}
	return true, nil
}
