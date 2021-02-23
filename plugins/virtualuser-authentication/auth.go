package virtualuser_authentication

import (
	"fmt"
	"github.com/c653labs/pggateway"
	"github.com/c653labs/pgproto"
	"strings"
)

func (p *VirtualUserAuth) AuthenticateClient(sess *pggateway.Session) (err error) {

	// Client authentication
	customUserName := string(sess.User)
	if _, ok := p.virtualCredentials[customUserName]; !ok {
		return fmt.Errorf("virtual user %s does not exist", customUserName)
	}

	rolpassword := p.virtualCredentials[customUserName]

	if strings.HasPrefix(rolpassword, "SCRAM-SHA-256$") {
		err := p.SCRAMSHA256ClientAuth(sess, rolpassword)
		if err != nil {
			return err
		}

	} else if strings.HasPrefix(rolpassword, "md5") {

		authReq, passwd, err := sess.GetUserPassword(pgproto.AuthenticationMethodMD5)
		if err != nil {
			return err
		}
		if !CheckMD5UserPassword([]byte(rolpassword[3:]), authReq.Salt, passwd.Password[3:]) {
			return fmt.Errorf("failed to login user %s, md5 password check failed", customUserName)
		}
	} else {

		_, passwd, err := sess.GetUserPassword(pgproto.AuthenticationMethodPlaintext)
		if err != nil {
			return err
		}
		if string(passwd.Password) != rolpassword {
			return fmt.Errorf("failed to login user %s, plaintext password check failed", customUserName)
		}

	}
	return nil
}

func (p *VirtualUserAuth) AuthOnServer(sess *pggateway.Session, startup *pgproto.StartupMessage) (err error) {

	// Connecting to the postgresql server
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
		return err
	}

	srvMsg, err := sess.ParseServerResponse()
	if err != nil {
		return err
	}
	authResp, ok := srvMsg.(*pgproto.AuthenticationRequest)
	if !ok {
		return fmt.Errorf("unexpected response type from server request: %s", srvMsg)
	}
	if authResp.Method == pgproto.AuthenticationMethodOK {
		return sess.WriteToClient(authResp)
	}

	switch authResp.Method {
	case pgproto.AuthenticationMethodPlaintext:
		return sess.WriteToServer(&pgproto.PasswordMessage{Password: []byte(p.dbPassword)})
	case pgproto.AuthenticationMethodMD5:
		passwdReq := &pgproto.PasswordMessage{}
		passwdReq.SetPassword([]byte(p.dbUser), []byte(p.dbPassword), authResp.Salt)
		return sess.WriteToServer(passwdReq)
	case pgproto.AuthenticationMethodSASL:
		err = p.SCRAMSHA256ServerAuth(sess, authResp)
		if err != nil {
			return err
		}

		return nil
	default:
		return fmt.Errorf("unexpected password request method from server")
	}
}
