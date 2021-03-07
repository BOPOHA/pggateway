package virtualuser_authentication

import (
	"fmt"
	"github.com/c653labs/pggateway"
	"github.com/c653labs/pgproto"
	"github.com/xdg/scram"
)

// Gateway to Client
func SCRAMSHA256ClientAuth(sess *pggateway.Session, rolpassword string) error {

	authReq := &pgproto.AuthenticationRequest{
		Method:                   pgproto.AuthenticationMethodSASL,
		SupportedScramSHA256:     true,
		SupportedScramSHA256Plus: false,
	}
	//sess.plugins.LogDebug(s.loggingContextWithMessage(message), "gateway request to client")

	err := sess.WriteToClient(authReq)

	if err != nil {
		return fmt.Errorf("write to client error: %v", err)
	}

	clientAuthResp, err := sess.ParseClientRequest()
	if err != nil {
		return fmt.Errorf("client does not support sasl auth: %v", err)
	}
	clientAuthMech, ok := clientAuthResp.(*pgproto.PasswordMessage)
	if !ok {
		return fmt.Errorf("client's sent not a Password Response: %v", err)
	}
	if len(clientAuthMech.BodyMessage) == 0 {
		return fmt.Errorf("client's sent not a SASLInitialResponse: %v", err)
	}
	if string(clientAuthMech.HeaderMessage) != pgproto.SASLMechanismScramSHA256 {
		return fmt.Errorf("client's SASL authentication mechanisms are not supported: %v", err)
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
	strMsg, err = conv.Step(string(clientAuthMech.BodyMessage))

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
		sess.WriteToClientEf("failed to authenticate user %s", string(sess.User))
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
