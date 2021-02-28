package passthrough

import (
	"fmt"
	"github.com/c653labs/pggateway"
	logging "github.com/c653labs/pggateway/plugins/file-logging"
	"github.com/c653labs/pgproto"
	"testing"
	"time"
)

var (
	config001 = []byte(`
listeners:
  - bind: ':5432'
    logging:
      file:
        level: 'debug'
        out: '-'
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
	pggateway.RegisterAuthPlugin("passthrough", NewPassthroughPlugin)
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

	err = sess.AuthOnServer("test", "test")

	if err != nil {
		t.Fatalf("error %s", err)
	}
	sm, err := sess.ParseServerResponse()

	if err != nil {
		t.Fatalf("error %s", err)
	}
	if sm, ok := sm.(*pgproto.Error); !ok {
		// "Message":"password authentication failed for user \"test\""
		t.Fatalf("expected Error message, got %T", sm)
	}

	// test with wright creds
	err = sess.ConnectToTarget(c.Listeners[0].Bind)
	if err != nil {
		t.Fatalf("error %s", err)
	}
	err = sess.AuthOnServer("plaintestrole", "plaintestpassword")

	if err != nil {
		t.Fatalf("error %s", err)
	}
	sm, err = sess.ParseServerResponse()

	if err != nil {
		t.Fatalf("error %s", err)
	}
	if _, ok := sm.(*pgproto.AuthenticationRequest); !ok {
		// "Message":"password authentication failed for user \"test\""
		t.Fatalf("expected Error message, got %#v", sm)
	}
	//fmt.Printf("%#v: ", sm)
	fmt.Println("ALLO")
	time.Sleep(200 * time.Millisecond) // waiting for server starts
}
