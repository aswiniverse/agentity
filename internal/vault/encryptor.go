package vault

// Encryptor defines the interface for encrypting and decrypting credential values.
type Encryptor interface {
	Encrypt(plaintext []byte) (ciphertext, iv []byte, keyVersion string, err error)
	Decrypt(ciphertext, iv []byte, keyVersion string) ([]byte, error)
}
