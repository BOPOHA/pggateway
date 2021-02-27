package virtualuser_authentication

//import (
//	"fmt"
//	"github.com/c653labs/pggateway"
//	"net"
//	"testing"
//)
//
//var (
//config001 = []byte(`
//logging:
//  file:
//    level: 'debug'
//    out: '-'
//listeners:
//  '127.0.0.1:2345':
//    target:
//      host: '127.0.0.1'
//      port: 2345
//    authentication:
//      virtualuser-authentication:
//        virtualusers:
//          zoo: 'md55dbb0a6ccb20a0399b301f69616cf4ca' # echo -n pass1zoo | md5sum
//          arni: 'pass2'
//          username: 'SCRAM-SHA-256$4096:CCKYO5ux7oZ5CcIMzDXw/A==$I0vnZaWMaqCF2xR3/+lMgXwJZKdHILWKFsQm3QpgRp0=:TBiVAuxlUrYOBqnvsVzFISHxwG+aqAyWUcC8ovl5pGs=' # securepassword
//          user: 'SCRAM-SHA-256$4096:iLSPyp46KvvOqk'
//        db:
//          ssl: false
//          user: 'test'
//          password: 'test'
//    logging:
//      file:
//        level: 'debug'
//        out: '-'
//    databases:
//      '*':
//`)
//)
//
//
//func TestClienServerConvPlain(t *testing.T) {
//	var err error
//	c := pggateway.NewConfig()
//	err = c.Unmarshal(config001)
//	if err != nil {
//		t.Fatal(err)
//	}
//	curListener := c.Listeners["127.0.0.1:2345"]
//	address := curListener.Bind
//	println(address)
//	l, err := net.Listen("tcp", address)
//	if err != nil {
//		t.Fatalf("error %s", err)
//	}
//	server, err := l.Accept()
//	if err != nil {
//		t.Fatalf("error %s", err)
//	}
//	client, err := net.Dial("tcp", address)
//	if err != nil {
//		t.Fatalf("error connecting to server %#v: %s", address, err)
//	}
//	plugins, err := pggateway.NewPluginRegistry(curListener.Authentication, curListener.Logging)
//	if err != nil {
//		t.Fatalf("error %s", err)
//	}
//	sess, err  := pggateway.NewSession(nil,nil,nil, false, client, server, plugins)
//	if err != nil {
//		t.Fatalf("error %s", err)
//	}
//	pp, err := NewVirtualUserPlugin(curListener.Authentication["virtualuser-authentication"])
//	if err != nil {
//		t.Fatalf("error %s", err)
//	}
//	//p, ok  := pp.(pggateway.VirtualUserAuth)
//	p, ok := pp.(*VirtualUserAuth)
//	if !ok {
//
//		t.Fatalf("error not ok")
//	}
//	err = p.AuthOnServer(sess, nil)
//	if err != nil {
//		t.Fatalf("error %s", err)
//	}
//	fmt.Println("ALLO")
//}
