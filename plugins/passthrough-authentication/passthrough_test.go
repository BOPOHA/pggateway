package passthrough

import (
	"github.com/c653labs/pggateway"
	"github.com/c653labs/pgproto"
	"testing"
	"time"
)

var (
	config001 = []byte(`
listeners:
  - bind: ':5432'
    authentication:
      passthrough:
        target:
          host: '127.0.0.1'
          port: 5430
`)
)

func TestClienServerConvPlainText(t *testing.T) {
	var err error
	c := pggateway.NewConfig()
	err = c.Unmarshal(config001)
	if err != nil {
		t.Fatal(err)
	}
	pggateway.RegisterAuthPlugin("passthrough", newPassthroughPlugin)
	//pggateway.RegisterLoggingPlugin("file", logging.NewLoggingPlugin)
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
		t.Fatalf("error %v", err)
	}
	sess, err := pggateway.NewSession(&pgproto.StartupMessage{Options: initialOptions}, nil, nil, false, nil, nil, sessPlugins)

	if err != nil {
		t.Fatalf("error %v", err)
	}
	time.Sleep(200 * time.Microsecond) // waiting for server starts
	// test with fake creds
	err = sess.ConnectToTarget(c.Listeners[0].Bind)
	if err != nil {
		t.Fatalf("error %v", err)
	}

	err = sess.AuthOnServer("test", "test")

	if err != nil {
		t.Fatalf("error %v", err)
	}
	sm, err := sess.ParseServerResponse()

	if err != nil {
		t.Fatalf("error %v", err)
	}
	if sm, ok := sm.(*pgproto.Error); !ok {
		// "BodyMessage":"password authentication failed for user \"test\""
		t.Fatalf("expected Error message, got %T", sm)
	}

	// test with wright creds
	err = sess.ConnectToTarget(c.Listeners[0].Bind)
	if err != nil {
		t.Fatalf("error %v", err)
	}
	err = sess.AuthOnServer("plaintestrole", "plaintestpassword")

	if err != nil {
		t.Fatalf("error %v", err)
	}
	sm, err = sess.ParseServerResponse()

	if err != nil {
		t.Fatalf("error %v", err)
	}
	if _, ok := sm.(*pgproto.AuthenticationRequest); !ok {
		// Expected &pgproto.AuthenticationRequest{
		// Method:0, Salt:[]uint8(nil), SupportedScramSHA256:false, SupportedScramSHA256Plus:false, BodyMessage:[]uint8(nil)}
		t.Fatalf("expected Error message, got %#v", sm)
	}
	//fmt.Printf("%#v: ", sm)
	//time.Sleep(200 * time.Millisecond)
}
