package virtualuser_authentication

import (
	"fmt"
	"github.com/c653labs/pggateway"
	"github.com/c653labs/pgproto"
	"github.com/xdg/scram"
)

// Gateway to PG server
func (p VirtualUserAuth) SCRAMSHA256ServerAuth(sess *pggateway.Session, authResp *pgproto.AuthenticationRequest) (err error) {
	var scramClient *scram.Client
	var scramMechanism, strMsg string
	var rawMsg []byte

	if authResp.SupportedScramSHA256 {
		scramClient, err = scram.SHA256.NewClient(p.dbUser, p.dbPassword, "")
		if err != nil {
			return fmt.Errorf("creating %s client %s", pgproto.SASLMechanismScramSHA256, err)
		}
		scramMechanism = pgproto.SASLMechanismScramSHA256

	} else if authResp.SupportedScramSHA256Plus {
		return fmt.Errorf("%s is not supported yet", pgproto.SASLMechanismScramSHA256Plus)
	} else {
		return fmt.Errorf("no found supported sasl mechanisms")
	}

	conv := scramClient.NewConversation()
	strMsg, err = conv.Step("")
	if err != nil {
		return fmt.Errorf("error creating first scram msg %s", err)
	}

	initSASLResponse := &pgproto.SASLInitialResponse{Mechanism: scramMechanism, Message: []byte(strMsg)}
	rawMsg, err = sess.GetAuthMessageFromServer(initSASLResponse)
	if err != nil {
		return err
	}
	strMsg, err = conv.Step(string(rawMsg))
	if err != nil {
		return fmt.Errorf("second sasl challenge failed: %s", err)
	}

	nextSASLResponse := &pgproto.SASLResponse{Message: []byte(strMsg)}
	rawMsg, err = sess.GetAuthMessageFromServer(nextSASLResponse)
	if err != nil {
		return err
	}

	strMsg, err = conv.Step(string(rawMsg))

	if err != nil {
		return fmt.Errorf("third sasl challenge failed: %s", err)
	}

	return nil
}

// Gateway to Client
func (p VirtualUserAuth) SCRAMSHA256ClientAuth(sess *pggateway.Session, rolpassword string) error {
	clientAuthMech, err := sess.GetAuthMessageFromClient(
		&pgproto.AuthenticationRequest{
			Method:                   pgproto.AuthenticationMethodSASL,
			SupportedScramSHA256:     true,
			SupportedScramSHA256Plus: false,
		})
	if err != nil {
		return fmt.Errorf("client does not support sasl auth: %s", err)
	}
	if clientAuthMech.Mechanism != pgproto.SASLMechanismScramSHA256 {
		return fmt.Errorf("client's SASL authentication mechanisms are not supported: %s", err)
	}
	storedCredentials, err := GetStoredCredentialsFromString(rolpassword)

	if err != nil {
		// TODO: will need do this check in newVirtualUserPlugin()
		return fmt.Errorf("cant validate stored creds: %s", err)
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
		return fmt.Errorf("failed to start scram conversation server: %s", err)
	}
	conv := scramServer.NewConversation()
	var strMsg string
	strMsg, err = conv.Step(string(clientAuthMech.Message))

	if err != nil {
		// strMsg == "e=unknown-user"
		return fmt.Errorf("e=unknown-user: %s", err)
	}
	clientResp, err := sess.GetPasswordMessageFromClient(
		&pgproto.AuthenticationRequest{
			Method:  pgproto.AuthenticationMethodSASLContinue,
			Message: []byte(strMsg),
		})
	if err != nil {
		return fmt.Errorf("AuthenticationMethodSASLContinue error: %s", err)
	}

	strMsg, err = conv.Step(string(clientResp))
	if err != nil {
		// strMsg == "e=invalid-proof"
		sess.WriteToClient(&pgproto.Error{
			Severity: []byte("Fatal"),
			Message:  append([]byte("failed to authenticate user "), sess.User...),
		})
		return fmt.Errorf("auth failed")
	}
	err = sess.WriteToClient(&pgproto.AuthenticationRequest{
		Method:  pgproto.AuthenticationMethodSASLFinal,
		Message: []byte(strMsg),
	})
	if err != nil {
		return fmt.Errorf("AuthenticationMethodSASLFinal error: %s", err)
	}
	return nil
}
