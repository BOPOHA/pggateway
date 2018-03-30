package pggateway

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"github.com/c653labs/pgproto"
	uuid "github.com/satori/go.uuid"
)

type Session struct {
	ID       string
	User     []byte
	Database []byte

	client   net.Conn
	server   net.Conn
	salt     []byte
	password []byte

	startup *pgproto.StartupMessage

	stopped bool

	plugins *PluginRegistry
}

func NewSession(client net.Conn, server net.Conn, plugins *PluginRegistry) (*Session, error) {
	var err error
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	return &Session{
		ID:      id.String(),
		client:  client,
		server:  server,
		salt:    generateSalt(),
		plugins: plugins,
		stopped: false,
	}, nil
}

func (s *Session) Close() {
	if s.server != nil {
		s.server.Close()
	}
}

func (s *Session) String() string {
	return fmt.Sprintf("Session<ID=%#v, User=%#v, Database=%#v>", s.ID, string(s.User), string(s.Database))
}

func (s *Session) Handle() error {
	var err error
	s.startup, err = s.parseStartupMessage()
	if err != nil {
		return err
	}

	if s.startup.SSLRequest {
		return s.setupSSLConnection()
	}

	err = s.plugins.Authenticate(s, s.startup)
	if err != nil {
		return err
	}
	return s.proxy()
}

func (s *Session) setupSSLConnection() error {
	_, err := s.client.Write([]byte{'S'})
	if err != nil {
		return err
	}

	cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return err
	}

	// Upgrade the client connection to a TLS connection
	client := tls.Server(s.client, &tls.Config{
		Certificates: []tls.Certificate{cer},
	})
	client.Handshake()
	s.client = client

	return s.Handle()
}

func (s *Session) GetUserPassword() (*pgproto.AuthenticationRequest, *pgproto.PasswordMessage, error) {
	auth := &pgproto.AuthenticationRequest{
		Method: pgproto.AuthenticationMethodMD5,
		Salt:   s.salt,
	}
	err := s.WriteToClient(auth)
	if err != nil {
		return nil, nil, err
	}

	msg, err := s.ParseClientRequest()
	if err != nil {
		return nil, nil, err
	}

	pwdMsg, ok := msg.(*pgproto.PasswordMessage)
	if !ok {
		return nil, nil, fmt.Errorf("expected password message")
	}
	s.password = pwdMsg.Password

	return auth, pwdMsg, nil
}

func (s *Session) parseStartupMessage() (*pgproto.StartupMessage, error) {
	msg, err := s.ParseClientRequest()
	if err != nil {
		return nil, err
	}

	switch m := msg.(type) {
	case *pgproto.StartupMessage:
		// Only extract options if this isn't an SSL request
		if m.SSLRequest {
			return m, nil
		}

		var ok bool
		if s.User, ok = m.Options["user"]; !ok {
			return nil, fmt.Errorf("no username sent with startup message")
		}

		if s.Database, ok = m.Options["database"]; !ok {
			return nil, fmt.Errorf("no database name sent with startup message")
		}

		return m, nil
	}
	return nil, fmt.Errorf("unexpected message type")
}

func (s *Session) authenticateWithServer(password []byte) error {
	err := s.WriteToServer(s.startup)
	if err != nil {
		return err
	}

	msg, err := s.ParseServerResponse()
	if err != nil {
		return err
	}
	var auth *pgproto.AuthenticationRequest
	var ok bool
	auth, ok = msg.(*pgproto.AuthenticationRequest)
	if !ok {
		return fmt.Errorf("expected authentication request")
	}

	// Requires password
	if auth.Method != pgproto.AuthenticationMethodOK {
		pwdMsg := &pgproto.PasswordMessage{}
		// Use the salt from the server, not our session salt
		pwdMsg.SetPassword(s.User, password, auth.Salt)
		err = s.WriteToServer(pwdMsg)
		if err != nil {
			return err
		}

		msg, err = s.ParseServerResponse()
		if err != nil {
			return err
		}

		auth = nil
		switch m := msg.(type) {
		case *pgproto.AuthenticationRequest:
			auth = m
		case *pgproto.Error:
			// TODO: Write generic cannot connect message?
			return s.WriteToClient(m)
		default:
			return fmt.Errorf("expected authentication request: %s", m)
		}

		if auth.Method != pgproto.AuthenticationMethodOK {
			return fmt.Errorf("expected successful authentication request")
		}
	}

	err = s.WriteToClient(auth)
	return err
}

func (s *Session) proxy() error {
	stop := make(chan error)
	go s.proxyClientMessages(stop)
	go s.proxyServerMessages(stop)
	err := <-stop
	s.stopped = true

	return err
}

func (s *Session) proxyServerMessages(stop chan error) {
	for {
		msg, err := s.ParseServerResponse()
		if err != nil {
			stop <- err
			break
		}

		s.WriteToClient(msg)
	}
	stop <- nil
}

func (s *Session) proxyClientMessages(stop chan error) {
	for {
		msg, err := s.ParseClientRequest()
		if err != nil {
			stop <- err
			break
		}

		s.WriteToServer(msg)

		if _, ok := msg.(*pgproto.Termination); ok {
			break
		}
	}
	stop <- nil
}

func (s *Session) WriteToServer(msg pgproto.ClientMessage) error {
	_, err := msg.WriteTo(s.server)
	return err
}

func (s *Session) WriteToClient(msg pgproto.ServerMessage) error {
	_, err := msg.WriteTo(s.client)
	return err
}

func (s *Session) ParseClientRequest() (pgproto.ClientMessage, error) {
	msg, err := pgproto.ParseClientMessage(s.client)
	if err == io.EOF {
		return msg, io.EOF
	}

	if err != nil {
		if !s.stopped {
			s.plugins.LogError(s.loggingContext(), "error parsing client request: %s", err)
		}
	} else {
		s.plugins.LogInfo(s.loggingContext(), "client request: %s", msg)
	}
	return msg, err
}

func (s *Session) ParseServerResponse() (pgproto.ServerMessage, error) {
	msg, err := pgproto.ParseServerMessage(s.server)
	if err == io.EOF {
		return msg, io.EOF
	}

	if err != nil {
		if !s.stopped {
			s.plugins.LogError(s.loggingContext(), "error parsing server response: %#v", err)
		}
	} else {
		s.plugins.LogInfo(s.loggingContext(), "server response: %s", msg)
	}
	return msg, err
}

func (s *Session) loggingContext() LoggingContext {
	return LoggingContext{
		"session_id": s.ID,
		"user":       string(s.User),
		"database":   string(s.Database),
	}
}
