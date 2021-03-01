package virtualuser_authentication

import (
	"github.com/c653labs/pggateway"
	logging "github.com/c653labs/pggateway/plugins/file-logging"
	"github.com/c653labs/pgproto"
	"io"
	"testing"
	"time"
)

var (
	config002 = []byte(`
logging:
  file:
    level: 'debug'
    out: '-'
listeners:
  - bind: ':5432'
    logging:
      file:
        level: 'debug'
        out: '-'
    authentication:
      virtualuser-authentication:
        users:
          plaintestrole: 'plaintestpassword'
          username: 'SCRAM-SHA-256$4096:CCKYO5ux7oZ5CcIMzDXw/A==$I0vnZaWMaqCF2xR3/+lMgXwJZKdHILWKFsQm3QpgRp0=:TBiVAuxlUrYOBqnvsVzFISHxwG+aqAyWUcC8ovl5pGs='
        target:
          host: '127.0.0.1'
          port: 5432
`)
)

func TestClienServerConvSCRAMSHA256(t *testing.T) {
	var err error
	c := pggateway.NewConfig()
	err = c.Unmarshal(config002)
	if err != nil {
		t.Fatal(err)
	}
	pggateway.RegisterAuthPlugin("virtualuser-authentication", newVirtualUserPlugin)
	pggateway.RegisterLoggingPlugin("file", logging.NewLoggingPlugin)
	s, err := pggateway.NewServer(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go func() {
		err = s.Start()
		if err != nil {
			t.Fatalf("error starting: %#v", err)
		}
	}()

	//AuthOnServer
	sessConfig := c.Listeners[0]
	initialOptions := map[string][]byte{"database": []byte("test")}
	sessPlugins, err := pggateway.NewPluginRegistry(sessConfig.Authentication, sessConfig.Logging)
	if err != nil {
		t.Fatalf("error %s", err)
	}
	sess, err := pggateway.NewSession(&pgproto.StartupMessage{Options: initialOptions}, nil, nil, false, nil, nil, sessPlugins)

	if err != nil {
		t.Fatalf("error %s", err)
	}
	time.Sleep(200 * time.Microsecond) // waiting for server starts
	// test with fake creds
	err = sess.ConnectToTarget(c.Listeners[0].Bind)
	if err != nil {
		t.Fatalf("error %s", err)
	}

	err = sess.AuthOnServer("username", "fakesecurepassword")

	if err == nil {
		t.Fatalf("Expected error")
	}
	sm, err := sess.ParseServerResponse()

	if err != nil && err != io.EOF {
		t.Fatalf("error %s", err)
	}
	if sm, ok := sm.(*pgproto.Error); !ok {
		// "Message":"password authentication failed for user \"test\""
		if err != io.EOF {
			t.Fatalf("expected Error message, got %#v", sm)
		}
	}

	// test with wright creds
	err = sess.ConnectToTarget(c.Listeners[0].Bind)
	//sess.
	if err != nil {
		t.Fatalf("error %s", err)
	}
	err = sess.AuthOnServer("username", "securepassword")

	if err != nil {
		t.Fatalf("error %s", err)
	}
	sm, err = sess.ParseServerResponse()

	if err != nil && err != io.EOF {
		t.Fatalf("error %s", err)
	}
	if _, ok := sm.(*pgproto.AuthenticationRequest); !ok {
		// Expected &pgproto.AuthenticationRequest{
		// Method:0, Salt:[]uint8(nil), SupportedScramSHA256:false, SupportedScramSHA256Plus:false, Message:[]uint8(nil)}
		t.Fatalf("expected Error message, got %#v", sm)
	}
	//fmt.Printf("%#v: ", sm)
	//time.Sleep(200 * time.Millisecond)
}
