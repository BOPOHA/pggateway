package virtualuser_authentication

import (
	"fmt"

	"github.com/c653labs/pggateway"
	"github.com/c653labs/pgproto"
)

type VirtualUser struct {
	customAuthMap map[string]string
	dbUser        string
	dbPassword    string
	dbSSL         bool
}

func init() {
	pggateway.RegisterAuthPlugin("virtualuser", newVirtualUserPlugin)
}

func newVirtualUserPlugin(config pggateway.ConfigMap) (pggateway.AuthenticationPlugin, error) {
	var ok bool
	auth := &VirtualUser{}

	// hardcode for now
	auth.customAuthMap = map[string]string{"zoo": "pass1", "arni": "pass2"}

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

func (p *VirtualUser) Authenticate(sess *pggateway.Session, startup *pgproto.StartupMessage) (bool, error) {

	if !sess.IsSSL {
		return false, fmt.Errorf("HPF requires an SSL session")
	}
	customUserName := string(sess.User)
	if _, ok := p.customAuthMap[customUserName]; !ok {
		return false, fmt.Errorf("virtual user %s is not allowed to access database", customUserName)
	}

	_, passwd, err := sess.GetUserPassword(pgproto.AuthenticationMethodPlaintext)
	if err != nil {
		return false, err
	}
	if string(passwd.Password) != p.customAuthMap[customUserName] {
		return false, fmt.Errorf("failed to login user %s, bad password", customUserName)
	}

	startupReq := &pgproto.StartupMessage{
		SSLRequest: p.dbSSL,
		Options: map[string][]byte{
			"user": []byte(p.dbUser),
		},
	}
	for k, v := range startup.Options {
		if k == "user" {
			continue
		}
		startupReq.Options[k] = v
	}

	err = sess.WriteToServer(startupReq)
	if err != nil {
		return false, err
	}

	srvMsg, err := sess.ParseServerResponse()
	if err != nil {
		return false, err
	}
	authResp, ok := srvMsg.(*pgproto.AuthenticationRequest)
	if !ok {
		return false, fmt.Errorf("unexpected response type from server request: %s", srvMsg)
	}
	if authResp.Method == pgproto.AuthenticationMethodOK {
		return true, sess.WriteToClient(authResp)
	}

	passwdReq := &pgproto.PasswordMessage{}
	switch authResp.Method {
	case pgproto.AuthenticationMethodPlaintext:
		passwdReq.Password = []byte(p.dbPassword)
	case pgproto.AuthenticationMethodMD5:
		passwdReq.SetPassword([]byte(p.dbUser), []byte(p.dbPassword), authResp.Salt)
	default:
		return false, fmt.Errorf("unexpected password request method from server")
	}

	return true, sess.WriteToServer(passwdReq)
}
