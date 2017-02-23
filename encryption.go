/*
 * Minio Go Library for Amazon S3 Compatible Cloud Storage (C) 2017 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package minio

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
)

// Unpad a set of bytes following PKCS5 algorithm
func pkcs5Unpad(buf []byte, blockSize int) ([]byte, error) {
	len := len(buf)
	if len == 0 {
		return nil, errors.New("buffer is empty")
	}
	pad := int(buf[len-1])
	if pad > len || pad > blockSize {
		return nil, errors.New("invalid padding size")
	}
	return buf[:len-pad], nil
}

// Pad a set of bytes following PKCS5 algorithm
func pkcs5Pad(buf []byte, blockSize int) ([]byte, error) {
	len := len(buf)
	pad := blockSize - (len % blockSize)
	padText := bytes.Repeat([]byte{byte(pad)}, pad)
	return append(buf, padText...), nil
}

// EncryptionKey - generic interface to encrypt/decrypt some bytes
type EncryptionKey interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

// SymmetricKey - encrypts data with a symmetric master key
type SymmetricKey struct {
	masterKey []byte
}

func (s *SymmetricKey) Encrypt(plain []byte) ([]byte, error) {
	// Initialize an AES encryptor using a master key
	keyBlock, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return []byte{}, err
	}

	// Pad the key before encryption
	plain, err = pkcs5Pad(plain, aes.BlockSize)

	encKey := []byte{}
	encPart := make([]byte, aes.BlockSize)

	// Encrypt the passed key by block
	for {
		if len(plain) < aes.BlockSize {
			break
		}
		// Encrypt the passed key
		keyBlock.Encrypt(encPart, plain[:aes.BlockSize])
		// Add the encrypted block to the total encrypted key
		encKey = append(encKey, encPart...)
		// Pass to the next plain block
		plain = plain[aes.BlockSize:]
	}
	return encKey, nil
}

func (s *SymmetricKey) Decrypt(cipher []byte) ([]byte, error) {
	// Initialize AES decrypter
	keyBlock, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}

	var plain []byte
	plainPart := make([]byte, aes.BlockSize)

	// Decrypt the encrypted data block by block
	for {
		if len(cipher) < aes.BlockSize {
			break
		}
		keyBlock.Decrypt(plainPart, cipher[:aes.BlockSize])
		// Add the decrypted block to the total result
		plain = append(plain, plainPart...)
		// Pass to the next cipher block
		cipher = cipher[aes.BlockSize:]
	}

	// Unpad the resulted plain data
	plain, err = pkcs5Unpad(plain, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return plain, nil
}

// NewSymmetricKey generates a new encrypt/decrypt crypto using
// an AES master key password
func NewSymmetricKey(b []byte) *SymmetricKey {
	return &SymmetricKey{masterKey: b}
}

// AsymmetricKey - struct which encrypts/decrypts data
// using RSA public/private certificates
type AsymmetricKey struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// Encrypt data using public key
func (a *AsymmetricKey) Encrypt(plain []byte) ([]byte, error) {
	cipher, err := rsa.EncryptPKCS1v15(rand.Reader, a.publicKey, plain)
	if err != nil {
		return nil, err
	}
	return cipher, nil
}

// Decrypt data using public key
func (a *AsymmetricKey) Decrypt(cipher []byte) ([]byte, error) {
	cipher, err := rsa.DecryptPKCS1v15(rand.Reader, a.privateKey, cipher)
	if err != nil {
		return nil, err
	}
	return cipher, nil
}

// NewAsymmetricKey - generates a crypto module able to encrypt/decrypt
// data using a pair for private and public key
func NewAsymmetricKey(privData []byte, pubData []byte) (*AsymmetricKey, error) {
	// Parse private key from passed data
	priv, err := x509.ParsePKCS8PrivateKey(privData)
	if err != nil {
		return nil, err
	}
	privKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not a valid private key")
	}

	// Parse public key from passed data
	pub, err := x509.ParsePKIXPublicKey(pubData)
	if err != nil {
		return nil, err
	}

	pubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not a valid public key")
	}

	// Associate the private key with the passed public key
	privKey.PublicKey = *pubKey

	return &AsymmetricKey{
		publicKey:  pubKey,
		privateKey: privKey,
	}, nil
}

type SecuredObject struct {
	internalReader io.Reader
	internalErr    error

	srcBuf *bytes.Buffer
	dstBuf *bytes.Buffer
	EOF    bool

	encryptionKey EncryptionKey

	contentKey []byte
	cryptedKey []byte

	iv      []byte
	matDesc []byte

	blockMode cipher.BlockMode

	pad      func([]byte, int) ([]byte, error)
	padInput bool
}

func NewSecuredObject(key EncryptionKey) *SecuredObject {
	return &SecuredObject{
		srcBuf:        bytes.NewBuffer([]byte{}),
		dstBuf:        bytes.NewBuffer([]byte{}),
		encryptionKey: key,
		matDesc:       []byte("{}"),
	}
}

func (s *SecuredObject) setEncryptMode() error {

	var err error

	s.srcBuf.Reset()
	s.dstBuf.Reset()
	s.EOF = false

	// Generate random content key
	s.contentKey = make([]byte, aes.BlockSize*2)
	if _, err = rand.Read(s.contentKey); err != nil {
		return err
	}
	// Encrypt content key
	s.cryptedKey, err = s.encryptionKey.Encrypt(s.contentKey)
	if err != nil {
		return err
	}
	// Generate random IV
	s.iv = make([]byte, aes.BlockSize)
	if _, err = rand.Read(s.iv); err != nil {
		return err
	}
	// New cipher
	encryptContentBlock, err := aes.NewCipher(s.contentKey)
	if err != nil {
		return err
	}

	s.blockMode = cipher.NewCBCEncrypter(encryptContentBlock, s.iv)

	s.pad = pkcs5Pad
	s.padInput = true

	return nil
}

func (s *SecuredObject) setDecryptMode(cryptedKey, iv []byte) error {
	var err error

	s.srcBuf.Reset()
	s.dstBuf.Reset()

	s.EOF = false

	s.iv = iv
	s.cryptedKey = cryptedKey

	// Decrypt content key
	s.contentKey, err = s.encryptionKey.Decrypt(s.cryptedKey)
	if err != nil {
		return err
	}

	// New cipher
	decryptContentBlock, err := aes.NewCipher(s.contentKey)
	if err != nil {
		return err
	}

	s.blockMode = cipher.NewCBCDecrypter(decryptContentBlock, s.iv)
	s.pad = pkcs5Unpad
	s.padInput = false

	return nil
}

func (s *SecuredObject) Read(buf []byte) (n int, err error) {

	// Always fill buf from bufChunk at the end of this function
	defer func() {
		if s.internalErr != nil {
			n, err = 0, s.internalErr
		} else {
			n, err = s.dstBuf.Read(buf)
		}
	}()

	if s.EOF {
		return
	}

	// Fill dest buffer if its length is less than buf
	for !s.EOF && s.dstBuf.Len() < len(buf) {

		srcPart := make([]byte, aes.BlockSize)
		dstPart := make([]byte, aes.BlockSize)

		// Fill src buffer
		for s.srcBuf.Len() < aes.BlockSize*2 {
			_, err = io.CopyN(s.srcBuf, s.internalReader, aes.BlockSize)
			if err != nil {
				break
			}
		}

		if err != nil && err != io.EOF {
			s.internalErr = err
			return 0, s.internalErr
		}

		s.EOF = (err == io.EOF)

		if s.EOF && s.padInput {
			if srcPart, err = s.pad(s.srcBuf.Bytes(), aes.BlockSize); err != nil {
				s.internalErr = err
				return
			}
		} else {
			_, _ = s.srcBuf.Read(srcPart)
		}

		for len(srcPart) > 0 {
			s.blockMode.CryptBlocks(dstPart, srcPart[:aes.BlockSize])
			if s.EOF && !s.padInput && len(srcPart) == aes.BlockSize {
				dstPart, err = s.pad(dstPart, aes.BlockSize)
				if err != nil {
					s.internalErr = err
					return
				}
			}
			if _, wErr := s.dstBuf.Write(dstPart); wErr != nil {
				return 0, wErr
			}
			srcPart = srcPart[aes.BlockSize:]
		}
	}

	return
}

func (s *SecuredObject) GetMetadata() (string, string, string) {
	return string(s.matDesc),
		base64.StdEncoding.EncodeToString(s.iv),
		base64.StdEncoding.EncodeToString(s.cryptedKey)
}
