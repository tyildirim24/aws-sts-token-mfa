package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

//Encrypt encrypts given input using the given key
func Encrypt(input string, key string) (string, error) {

	decodedKey, _ := hex.DecodeString(key)
	plaintext := []byte(input)

	block, err := aes.NewCipher(decodedKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext), nil
}

//Decrypt decrypts given encrypted string using the key
func Decrypt(input string, key string) (string, error) {

	decodedKey, _ := hex.DecodeString(key)
	enc, _ := hex.DecodeString(input)

	block, err := aes.NewCipher(decodedKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()

	if len(enc) < nonceSize {
		return "", errors.New("invalid encrypted input string")
	}

	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
