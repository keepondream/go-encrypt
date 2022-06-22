package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type RSA struct {
}

/** plainText: 需要加密的明文
* pubKeyBuf: 加密的公钥
* cipherText: 返回的密文
 */
func (r *RSA) Encrypt(plainText, pubKeyBuf []byte) (cipherText []byte, err error) {
	// 1.使用pem解码公钥
	block, _ := pem.Decode(pubKeyBuf)
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse publick key failed: %s", err)
	}
	pubKey := pubInterface.(*rsa.PublicKey)

	// 2.使用公钥对内容加密
	cipherText, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)
	if err != nil {
		return nil, fmt.Errorf("encrypt plain text failed: %s", err)
	}

	return cipherText, nil
}

/**
* cipherText: 需要解密的密文
* PriKeyBuf: 需要解密的私钥
* plainText: 返回的明文
 */
func (r *RSA) Decrypt(cipherText, PriKeyBuf []byte) (plainText []byte, err error) {
	// 1.使用pem解码公钥
	block, _ := pem.Decode(PriKeyBuf)
	priInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key failed: %s", err)
	}

	priKey := priInterface.(*rsa.PrivateKey)

	// 2.使用私钥对密文解密
	plainText, err = rsa.DecryptPKCS1v15(rand.Reader, priKey, cipherText)
	if err != nil {
		return nil, fmt.Errorf("decrypt cipher text failed: %s", err)
	}

	return plainText, nil
}
