package certdeck

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
)

// https://www.reddit.com/r/golang/comments/m1sjfs/comment/gqfoq26/

func HashRSA(src *rsa.PublicKey) []byte {
	hasher := sha1.New()
	hasher.Write(src.N.Bytes())
	return hasher.Sum(nil)
}

func HashECDSA(src *ecdsa.PublicKey) []byte {
	hasher := sha1.New()
	hasher.Write(src.X.Bytes())
	hasher.Write(src.Y.Bytes())
	return hasher.Sum(nil)
}

func HashED25519(src *ed25519.PublicKey) []byte {
	hasher := sha1.New()
	hasher.Write(*src)
	return hasher.Sum(nil)
}
