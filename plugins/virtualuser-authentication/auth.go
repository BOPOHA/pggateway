package virtualuser_authentication

import (
	"fmt"
	"github.com/c653labs/pggateway"
	"github.com/c653labs/pgproto"
	"github.com/xdg/scram"
	"strings"
)

func (p *VirtualuserAuthentications) AuthenticateClient(sess *pggateway.Session) (err error) {

	// Client authentication
	customUserName := string(sess.User)
	rolpassword := p.GetRolePassword(customUserName)

	if strings.HasPrefix(rolpassword, "SCRAM-SHA-256$") {
		storedCredentials, err := pggateway.GetSCRAMStoredCredentials(rolpassword)
		if err != nil {
			return fmt.Errorf("cant validate stored creds: %v", err)
		}
		credentiallookup := func(s string) (scram.StoredCredentials, error) {
			// TODO: in SCRAM-...-PLUS will need additional check:
			//if s != customUserName {
			//	return scram.StoredCredentials{}, fmt.Errorf("user not found")
			//}
			return storedCredentials, nil

		}
		err = sess.SCRAMSHA256ClientAuth(credentiallookup)

		return err

	} else if strings.HasPrefix(rolpassword, "md5") {

		authReq, passwd, err := sess.GetUserPassword(pgproto.AuthenticationMethodMD5)
		if err != nil {
			return err
		}
		if !pggateway.CheckMD5UserPassword([]byte(rolpassword[3:]), authReq.Salt, passwd.HeaderMessage[3:]) {
			return fmt.Errorf("failed to login user %s, md5 password check failed", customUserName)
		}
	} else {
		_, passwd, err := sess.GetUserPassword(pgproto.AuthenticationMethodPlaintext)
		if err != nil {
			return fmt.Errorf("failed to get password")
		}
		if string(passwd.HeaderMessage) != rolpassword {
			return fmt.Errorf("failed to login user %s, plaintext password check failed", customUserName)
		}

	}
	return nil
}
