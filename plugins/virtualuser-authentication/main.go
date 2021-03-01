package virtualuser_authentication

// https://www.postgresql.org/docs/11/protocol-flow.html
// https://www.postgresql.org/docs/11/sasl-authentication.html
// https://www.postgresql.org/docs/11/protocol-message-formats.html

import (
	"fmt"
	"github.com/c653labs/pggateway"
)

// VirtualuserAuthentication
type VirtualuserAuthentications struct {
	UserMap map[string]VirtualuserAuthentication
}

type VirtualuserAuthentication struct {
	Name   string                 `json:"name"`
	Target pggateway.TargetConfig `json:"target"`
	Users  map[string]string      `json:"users"`
	//Logging Logging           `json:"logging"`
}

func init() {
	pggateway.RegisterAuthPlugin("virtualuser-authentication", newVirtualUserPlugin)
}

func newVirtualUserPlugin(config interface{}) (plugin pggateway.AuthenticationPlugin, err error) {
	auths := &[]VirtualuserAuthentication{}
	err = pggateway.FillStruct(config, auths)

	usernameMapping := make(map[string]VirtualuserAuthentication)
	for _, auth := range *auths {
		for username := range auth.Users {
			usernameMapping[username] = auth
		}
	}
	plugin = &VirtualuserAuthentications{
		UserMap: usernameMapping,
	}
	//fmt.Printf("RESEULP: %#v\n\n%#v\n\n%v\n", plugin, config, err)
	return
}

func (p *VirtualuserAuthentications) Authenticate(sess *pggateway.Session) (bool, error) {
	vuauth, ok := p.UserMap[string(sess.User)]
	if !ok {
		return false, fmt.Errorf("virtual user %s does not exist", sess.User)
	}

	if !pggateway.IsDatabaseAllowed(vuauth.Target.Databases, sess.Database) {
		return false, sess.WriteToClientEf("IsDatabaseAllowed returns False")
	}
	err := p.AuthenticateClient(sess)
	if err != nil {
		return false, err
	}
	err = sess.DialToS(vuauth.Target.Host, vuauth.Target.Port)
	if err != nil {
		return false, err
	}
	err = sess.AuthOnServer(vuauth.Target.User, vuauth.Target.Password)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (p *VirtualuserAuthentications) GetRolePassword(username string) string {
	return p.UserMap[username].Users[username]
}
