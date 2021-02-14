package virtualuser_authentication

import (
	"fmt"

	"github.com/c653labs/pggateway"
	"github.com/c653labs/pgproto"
	"mellium.im/sasl"
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

	if !sess.IsSSL {
		return false, fmt.Errorf("HPF requires an SSL session")
	}
	customUserName := string(sess.User)
	if _, ok := p.virtualCredentials[customUserName]; !ok {
		return false, fmt.Errorf("virtual user %s does not exist", customUserName)
	}

	_, passwd, err := sess.GetUserPassword(pgproto.AuthenticationMethodPlaintext)
	if err != nil {
		return false, err
	}
	if string(passwd.Password) != p.virtualCredentials[customUserName] {
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

	switch authResp.Method {
	case pgproto.AuthenticationMethodPlaintext:
		return true, sess.WriteToServer(&pgproto.PasswordMessage{Password: []byte(p.dbPassword)})
	case pgproto.AuthenticationMethodMD5:
		passwdReq := &pgproto.PasswordMessage{}
		passwdReq.SetPassword([]byte(p.dbUser), []byte(p.dbPassword), authResp.Salt)
		return true, sess.WriteToServer(passwdReq)
	case pgproto.AuthenticationMethodSASL:
		var authMech sasl.Mechanism
		if authResp.SupportedScramSHA256 {
			authMech = sasl.ScramSha256
		} else if authResp.SupportedScramSHA256Plus {
			// TODO: scram-sha-256-plus is not implemented now
			authMech = sasl.ScramSha256Plus
		}
		creds := sasl.Credentials(func() ([]byte, []byte, []byte) {
			return []byte(p.dbUser), []byte(p.dbPassword), []byte{}
		})
		sc := sasl.NewClient(authMech, creds)
		_, scMsg, err := sc.Step(nil)
		if err != nil {
			return false, fmt.Errorf("error creating first scram msg %s", err)
		}

		initSASLResponse := &pgproto.SASLInitialResponse{Mechanism: authMech.Name, Message: scMsg}
		scMsg, err = sess.GetAuthMessageFromServer(initSASLResponse)
		if err != nil {
			return false, err
		}
		_, scMsg, err = sc.Step(scMsg)
		if err != nil {
			return false, fmt.Errorf("second sasl challenge failed: %s", err)
		}

		nextSASLResponse := &pgproto.SASLResponse{Message: scMsg}
		scMsg, err = sess.GetAuthMessageFromServer(nextSASLResponse)
		if err != nil {
			return false, err
		}

		_, scMsg, err = sc.Step(scMsg)
		if err != nil {
			return false, fmt.Errorf("third sasl challenge failed: %s", err)
		}

		return true, nil
	default:
		return false, fmt.Errorf("unexpected password request method from server")
	}
}
