package virtualuser_authentication

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/xdg/scram"
	"strconv"
	"strings"
)

// CheckMD5UserPassword
func CheckMD5UserPassword(md5UserPassword, salt, md5SumWithSalt []byte) bool {

	digest := md5.New()
	digest.Write(md5UserPassword)
	digest.Write(salt)
	hash := digest.Sum(nil)

	encodedHash := make([]byte, hex.EncodedLen(len(hash)))
	hex.Encode(encodedHash, hash)
	return bytes.Equal(encodedHash, md5SumWithSalt)
}

func GetStoredCredentialsFromString(scramrolpassword string) (creds scram.StoredCredentials, err error) {
	// strMec, strIter, strSalt, strStorKey, strSrvKey
	s := strings.Split(strings.ReplaceAll(scramrolpassword, "$", ":"), ":")
	if len(s) != 5 {
		return creds, fmt.Errorf("bad rolpassword format")
	}
	i, err := strconv.Atoi(s[1])
	if err != nil {
		return creds, fmt.Errorf("bad iter")
	}
	salt, err := base64.StdEncoding.DecodeString(s[2])
	if err != nil {
		return creds, fmt.Errorf("bad salt")
	}
	storKey, err := base64.StdEncoding.DecodeString(s[3])
	if err != nil {
		return creds, fmt.Errorf("bad storKey")
	}
	servKey, err := base64.StdEncoding.DecodeString(s[4])
	if err != nil {
		return creds, fmt.Errorf("bad servKey")
	}

	return scram.StoredCredentials{
		KeyFactors: scram.KeyFactors{
			Salt:  string(salt),
			Iters: i,
		},
		StoredKey: storKey,
		ServerKey: servKey,
	}, nil
}
