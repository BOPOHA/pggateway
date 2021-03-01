package virtualuser_authentication

import (
	"fmt"
	"github.com/c653labs/pggateway"
	"github.com/c653labs/pgproto"
	"strings"
)

func (p *VirtualuserAuthentications) AuthenticateClient(sess *pggateway.Session) (err error) {

	// Client authentication
	customUserName := string(sess.User)
	rolpassword := p.GetRolePassword(customUserName)

	if strings.HasPrefix(rolpassword, "SCRAM-SHA-256$") {
		err := SCRAMSHA256ClientAuth(sess, rolpassword)
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
			return fmt.Errorf("failed to get password")
		}
		if string(passwd.Password) != rolpassword {
			return fmt.Errorf("failed to login user %s, plaintext password check failed", customUserName)
		}

	}
	return nil
}
