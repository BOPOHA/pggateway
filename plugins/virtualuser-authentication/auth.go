package virtualuser_authentication

// https://www.postgresql.org/docs/11/protocol-flow.html
// https://www.postgresql.org/docs/11/sasl-authentication.html
// https://www.postgresql.org/docs/11/protocol-message-formats.html

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/c653labs/pggateway"
	"github.com/c653labs/pgproto"
	"github.com/xdg/scram"
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

	// Client authentication
	customUserName := string(sess.User)
	if _, ok := p.virtualCredentials[customUserName]; !ok {
		return false, fmt.Errorf("virtual user %s does not exist", customUserName)
	}

	rolpassword := p.virtualCredentials[customUserName]

	if strings.HasPrefix(rolpassword, "SCRAM-SHA-256$") {
		clientAuthMech, err := sess.GetAuthMessageFromClient(&pgproto.AuthenticationRequest{Method: pgproto.AuthenticationMethodSASL, SupportedScramSHA256: true, SupportedScramSHA256Plus: false})
		if err != nil {
			return false, fmt.Errorf("client does not support sasl auth: %s", err)
		}
		if clientAuthMech.Mechanism != pgproto.SASLMechanismScramSHA256 {
			return false, fmt.Errorf("client's SASL authentication mechanisms are not supported: %s", err)
		}
		storedCredentials, err := GetStoredCredentialsFromString(rolpassword)

		if err != nil {
			// TODO: will need do this check in newVirtualUserPlugin()
			return false, fmt.Errorf("cant validate stored creds: %s", err)
		}
		credentiallookup := func(s string) (scram.StoredCredentials, error) {
			// TODO: in SCRAM-...-PLUS will need additional check:
			//if s != customUserName {
			//	return scram.StoredCredentials{}, fmt.Errorf("user not found")
			//}
			return storedCredentials, nil

		}
		scramServer, err := scram.SHA256.NewServer(credentiallookup)
		if err != nil {
			return false, fmt.Errorf("failed to start scram conversation server: %s", err)
		}
		conv := scramServer.NewConversation()
		var strMsg string
		strMsg, err = conv.Step(string(clientAuthMech.Message))

		if err != nil {
			// strMsg == "e=unknown-user"
			return false, fmt.Errorf("e=unknown-user: %s", err)
		}
		clientResp, err := sess.GetMessageFromClient(
			&pgproto.AuthenticationRequest{
				Method:  pgproto.AuthenticationMethodSASLContinue,
				Message: []byte(strMsg),
			})
		if err != nil {
			return false, fmt.Errorf("AuthenticationMethodSASLContinue error: %s", err)
		}

		strMsg, err = conv.Step(string(clientResp))
		if err != nil {
			// strMsg == "e=invalid-proof"
			sess.WriteToClient(&pgproto.Error{
				Severity: []byte("Fatal"),
				Message:  append([]byte("failed to authenticate user "), sess.User...),
			})
			return false, fmt.Errorf("auth failed")
		}
		err = sess.WriteToClient(&pgproto.AuthenticationRequest{
			Method:  pgproto.AuthenticationMethodSASLFinal,
			Message: []byte(strMsg),
		})
		if err != nil {
			return false, fmt.Errorf("AuthenticationMethodSASLFinal error: %s", err)
		}

	} else if strings.HasPrefix(rolpassword, "md5") {

		authReq, passwd, err := sess.GetUserPassword(pgproto.AuthenticationMethodMD5)
		if err != nil {
			return false, err
		}
		if !CheckMD5UserPassword([]byte(rolpassword[3:]), authReq.Salt, passwd.Password[3:]) {
			return false, fmt.Errorf("failed to login user %s, md5 password check failed", customUserName)
		}
	} else {

		_, passwd, err := sess.GetUserPassword(pgproto.AuthenticationMethodPlaintext)
		if err != nil {
			return false, err
		}
		if string(passwd.Password) != rolpassword {
			return false, fmt.Errorf("failed to login user %s, plaintext password check failed", customUserName)
		}

	}

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

	err := sess.WriteToServer(startupReq)
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
		var scramClient *scram.Client
		var scramMechanism, strMsg string
		var rawMsg []byte

		if authResp.SupportedScramSHA256 {
			scramClient, err = scram.SHA256.NewClient(p.dbUser, p.dbPassword, "")
			if err != nil {
				return false, fmt.Errorf("creating %s client %s", pgproto.SASLMechanismScramSHA256, err)
			}
			scramMechanism = pgproto.SASLMechanismScramSHA256

		} else if authResp.SupportedScramSHA256Plus {
			return false, fmt.Errorf("%s is not supported yet", pgproto.SASLMechanismScramSHA256Plus)
		} else {
			return false, fmt.Errorf("no found supported sasl mechanisms")
		}

		conv := scramClient.NewConversation()
		strMsg, err := conv.Step("")
		if err != nil {
			return false, fmt.Errorf("error creating first scram msg %s", err)
		}

		initSASLResponse := &pgproto.SASLInitialResponse{Mechanism: scramMechanism, Message: []byte(strMsg)}
		rawMsg, err = sess.GetAuthMessageFromServer(initSASLResponse)
		if err != nil {
			return false, err
		}
		strMsg, err = conv.Step(string(rawMsg))
		if err != nil {
			return false, fmt.Errorf("second sasl challenge failed: %s", err)
		}

		nextSASLResponse := &pgproto.SASLResponse{Message: []byte(strMsg)}
		rawMsg, err = sess.GetAuthMessageFromServer(nextSASLResponse)
		if err != nil {
			return false, err
		}

		strMsg, err = conv.Step(string(rawMsg))

		if err != nil {
			return false, fmt.Errorf("third sasl challenge failed: %s", err)
		}

		return true, nil
	default:
		return false, fmt.Errorf("unexpected password request method from server")
	}
}

// CheckMD5UserPassword
func CheckMD5UserPassword(md5UserPassword, salt, md5SumWithSalt []byte) bool {

	digest := md5.New()
	digest.Write(md5UserPassword)
	digest.Write(salt)
	hash := digest.Sum(nil)

	encodedHash := make([]byte, hex.EncodedLen(len(hash)))
	hex.Encode(encodedHash, hash)
	return bytes.Equal(encodedHash, md5SumWithSalt)
}

func GetStoredCredentialsFromString(scramrolpassword string) (creds scram.StoredCredentials, err error) {
	// strMec, strIter, strSalt, strStorKey, strSrvKey
	s := strings.Split(strings.ReplaceAll(scramrolpassword, "$", ":"), ":")
	if len(s) != 5 {
		return creds, fmt.Errorf("bad rolpassword format")
	}
	i, err := strconv.Atoi(s[1])
	if err != nil {
		return creds, fmt.Errorf("bad iter")
	}
	salt, err := base64.StdEncoding.DecodeString(s[2])
	if err != nil {
		return creds, fmt.Errorf("bad salt")
	}
	storKey, err := base64.StdEncoding.DecodeString(s[3])
	if err != nil {
		return creds, fmt.Errorf("bad storKey")
	}
	servKey, err := base64.StdEncoding.DecodeString(s[4])
	if err != nil {
		return creds, fmt.Errorf("bad servKey")
	}

	return scram.StoredCredentials{
		KeyFactors: scram.KeyFactors{
			Salt:  string(salt),
			Iters: i,
		},
		StoredKey: storKey,
		ServerKey: servKey,
	}, nil
}
