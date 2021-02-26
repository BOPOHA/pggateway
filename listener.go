package pggateway

import (
	"crypto/tls"
	"fmt"
	"github.com/c653labs/pgproto"
	"io"
	"net"
	"strconv"
)

type Listener struct {
	l        net.Listener
	config   *ListenerConfig
	plugins  *PluginRegistry
	stopping bool
}

func NewListener(config *ListenerConfig) *Listener {
	return &Listener{
		config:   config,
		stopping: false,
	}
}

func (l *Listener) Listen() error {
	l.stopping = false
	var err error
	l.plugins, err = NewPluginRegistry(l.config.Authentication, l.config.Logging)
	if err != nil {
		return err
	}

	l.l, err = net.Listen("tcp", l.config.Bind)
	if err != nil {
		return err
	}

	return nil
}

func (l *Listener) Close() error {
	l.stopping = true
	if l.l != nil {
		l.l.Close()
	}
	return nil
}

func (l *Listener) Handle() error {
	for {
		conn, err := l.l.Accept()
		if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
			continue
		}
		if err != nil {
			if l.stopping {
				return nil
			}
			l.plugins.LogError(nil, "error accepting client: %s", err)
			return err
		}

		go func(conn net.Conn) {
			defer conn.Close()
			err := l.handleClient(conn)
			if err != nil && err != io.EOF {
				l.plugins.LogError(nil, "error handling client session: %s", err)
			}
		}(conn)
	}
}

func (l *Listener) databaseAllowed(database []byte) bool {
	_, ok := l.config.Databases[string(database)]
	if ok {
		return true
	}

	_, ok = l.config.Databases["*"]
	return ok
}

func (l *Listener) preAuthClient(client net.Conn, s *Session) (err error) {

	startup, err := pgproto.ParseStartupMessage(client)
	if err != nil {
		return err
	}

	isSSL := false
	if startup.SSLRequest {
		if !l.config.SSL.Enabled {
			_, err := client.Write([]byte{'N'})
			return err
		}
		client, err = l.upgradeSSLConnection(client)
		if err != nil {
			return err
		}

		isSSL = true
		startup, err = pgproto.ParseStartupMessage(client)
		if err != nil {
			return err
		}
	} else if l.config.SSL.Required {
		// SSL is required but they didn't request it, return an error
		errMsg := &pgproto.Error{
			Severity: []byte("Fatal"),
			Message:  []byte("server does not support SSL, but SSL was required"),
		}
		_, err = pgproto.WriteMessage(errMsg, client)
		return err
	}

	var user []byte
	var database []byte
	var ok bool
	if user, ok = startup.Options["user"]; !ok {
		// No username was provided
		errMsg := &pgproto.Error{
			Severity: []byte("Fatal"),
			Message:  []byte("user startup option is required"),
		}
		_, err = pgproto.WriteMessage(errMsg, client)
		return err
	}

	if database, ok = startup.Options["database"]; !ok {
		// No database was provided
		errMsg := &pgproto.Error{
			Severity: []byte("Fatal"),
			Message:  []byte("database startup option is required"),
		}
		_, err = pgproto.WriteMessage(errMsg, client)
		return err
	}

	if !l.databaseAllowed(database) {
		// Database is nto supported
		errMsg := &pgproto.Error{
			Severity: []byte("Fatal"),
			Message:  []byte(fmt.Sprintf("unknown database %#v", string(database))),
		}
		_, err = pgproto.WriteMessage(errMsg, client)
		return err
	}
	s.User = user
	s.Database = database
	s.startup = startup
	s.IsSSL = isSSL
	s.client = client
	return
}

func (l *Listener) handleClient(client net.Conn) error {
	var err error
	sess := &Session{}
	if err := l.preAuthClient(client, sess); err != nil {
		l.plugins.LogError(nil, "error creating new client session: %s", err)
		client.Close()
		return err
	}
	sess.generateUID()
	sess.generateSalt()
	sess.plugins = l.plugins
	defer sess.Close()

	l.plugins.LogInfo(sess.loggingContext(), "new client session")
	err = sess.Handle()

	addr := net.JoinHostPort(l.config.Target.Host, strconv.Itoa(l.config.Target.Port))
	if err = sess.connectToTarget(addr); err != nil {
		return err
	}

	if err != nil {
		l.plugins.LogError(nil, "error connecting to server %#v: %s", addr, err)
		sess.WriteToClient(&pgproto.Error{
			Severity: []byte("Fatal"),
			Message:  []byte("error connecting to server, " + err.Error()),
		})
		return err
	}
	if err = sess.AuthOnServer(l.config.Target.User, l.config.Target.Password); err != nil {
		l.plugins.LogError(nil, "error auth to server %#v: %s", addr, err)
		sess.WriteToClient(&pgproto.Error{
			Severity: []byte("Fatal"),
			Message:  []byte("error auth to server, " + err.Error()),
		})
		return err
	}
	l.plugins.LogInfo(nil, "starting proxy")
	err = sess.proxy()
	if err != nil && err != io.EOF {
		l.plugins.LogError(sess.loggingContext(), "client session end: %s", err)
	} else {
		l.plugins.LogInfo(sess.loggingContext(), "client session end")
	}
	return err
}

func (l *Listener) upgradeSSLConnection(client net.Conn) (net.Conn, error) {
	_, err := client.Write([]byte{'S'})
	if err != nil {
		return nil, err
	}

	cer, err := tls.LoadX509KeyPair(l.config.SSL.Certificate, l.config.SSL.Key)
	if err != nil {
		return nil, err
	}

	// Upgrade the client connection to a TLS connection
	sslClient := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{cer},
	})
	sslClient.Handshake()

	return sslClient, nil
}

func (l *Listener) String() string {
	return l.config.Bind
}
