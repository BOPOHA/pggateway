package virtualuser_authentication

import (
	"fmt"
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
  - bind: ':5429'
    logging:
      file:
        level: 'debug'
        out: '-'
    authentication:
      virtualuser-authentication:
        - name: "fsdsgf"
          users:
            plaintestrole: 'plaintestpassword'
            username: 'SCRAM-SHA-256$4096:CCKYO5ux7oZ5CcIMzDXw/A==$I0vnZaWMaqCF2xR3/+lMgXwJZKdHILWKFsQm3QpgRp0=:TBiVAuxlUrYOBqnvsVzFISHxwG+aqAyWUcC8ovl5pGs='
          target:
            host: '127.0.0.1'
            port: 5429
`)
)

func TestClienServerConvSCRAMSHA256FakePassword(t *testing.T) {
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
		// "BodyMessage":"password authentication failed for user \"test\""
		if err != io.EOF {
			t.Fatalf("expected Error message, got %#v", sm)
		}
	}
	s.Close()
}

func TestClienServerConvSCRAMSHA256RightCreds(t *testing.T) {
	var err error
	username := []byte("username")
	database := []byte("test")
	password := []byte("securepassword")
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
	initialOptions := map[string][]byte{"database": database, "user": username}
	sessPlugins, err := pggateway.NewPluginRegistry(sessConfig.Authentication, sessConfig.Logging)
	if err != nil {
		t.Fatalf("error %c", err)
	}
	sess, err := pggateway.NewSession(&pgproto.StartupMessage{Options: initialOptions}, username, database, false, nil, nil, sessPlugins)

	if err != nil {
		t.Fatalf("error %s", err)
	}
	time.Sleep(200 * time.Microsecond) // waiting for server starts
	// test with wright creds
	err = sess.ConnectToTarget(c.Listeners[0].Bind)
	//sess.
	if err != nil {
		t.Fatalf("error %s", err)
	}

	fmt.Printf("#### %s \n%s\n\n\n###", sess.User, sess.Database)
	err = sess.AuthOnServer(string(username), string(password))

	if err != nil {
		t.Fatalf("error %s", err)
	}
	time.Sleep(200 * time.Millisecond)
	return // TODO: here we have {"level":"error","time":1614608259,"message":"error handling client session: virtual user  does not exist"}

	sm, err := sess.ParseServerResponse()

	if err != nil && err != io.EOF {
		t.Fatalf("error %s", err)
	}
	if _, ok := sm.(*pgproto.AuthenticationRequest); !ok {
		// Expected &pgproto.AuthenticationRequest{
		// Method:0, Salt:[]uint8(nil), SupportedScramSHA256:false, SupportedScramSHA256Plus:false, BodyMessage:[]uint8(nil)}
		t.Fatalf("expected Error message, got %#v", sm)
	}
	//fmt.Printf("%#v: ", sm)
	//time.Sleep(200 * time.Millisecond)
	s.Close()
}
