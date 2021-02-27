package pggateway

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
)

func generateSalt() []byte {
	salt := make([]byte, 4)
	binary.Read(rand.Reader, binary.BigEndian, &salt[0])
	binary.Read(rand.Reader, binary.BigEndian, &salt[1])
	binary.Read(rand.Reader, binary.BigEndian, &salt[2])
	binary.Read(rand.Reader, binary.BigEndian, &salt[3])
	return salt
}

func FillStruct(data map[string]interface{}, result interface{}) error {
	//t := reflect.ValueOf(result).Elem()
	//for k, v := range data {
	//	k = strings.Title(k)
	//	val := t.FieldByName(k)
	//	fmt.Printf("VAL %#v\nKEY %#v\nVALUE %#v\n", v, k, val)
	//	if !val.IsValid() {continue}
	//	val.Set(reflect.ValueOf(v))
	//}
	c, err := json.Marshal(data)

	if err != nil {
		return err
	}

	return json.Unmarshal(c, result)
}
