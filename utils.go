package pggateway

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/c653labs/pgproto"
	"io"
)

func generateSalt() []byte {
	salt := make([]byte, 4)
	binary.Read(rand.Reader, binary.BigEndian, &salt[0])
	binary.Read(rand.Reader, binary.BigEndian, &salt[1])
	binary.Read(rand.Reader, binary.BigEndian, &salt[2])
	binary.Read(rand.Reader, binary.BigEndian, &salt[3])
	return salt
}

func FillStruct(data interface{}, result interface{}) error {
	c, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(c, result)
}

func IsDatabaseAllowed(databases []string, database []byte) bool {
	if len(databases) == 0 {
		return true
	}
	for _, match := range databases {
		if match == string(database) {
			return true
		}
	}
	return false
}

func RetunErrorfAndWritePGMsg(out io.Writer, format string, a ...interface{}) error {
	msgString := fmt.Sprintf(format, a...)

	errMsg := &pgproto.Error{
		Severity: []byte("Fatal"),
		Message:  []byte(msgString),
	}
	_, _ = pgproto.WriteMessage(errMsg, out)

	return errors.New(msgString)
}
