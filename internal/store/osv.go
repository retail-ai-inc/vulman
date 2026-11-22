package store

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"os"

	"vulman/internal/apperror"
	"vulman/internal/osvdb"
)

func (s *Store) OpenOSVDatabase() (*osvdb.Store, error) {
	return osvdb.Open(s.root.Name(), s.aead)
}

// OpenOSVForScan never opens the master database or creates workspace files.
// A separate process must wait for the desktop to close its OSV database handle.
func OpenOSVForScan(dir string) (_ *osvdb.Store, resultErr error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := root.Close(); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	info, err := root.Lstat(keyFile)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != keySize {
		return nil, apperror.New("invalid_vulman_encryption_key_length", "invalid Vulman encryption key length")
	}
	key, err := loadOrCreateKey(root, false)
	if err != nil {
		return nil, err
	}
	if len(key) != keySize {
		return nil, apperror.New("invalid_vulman_encryption_key_length", "invalid Vulman encryption key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return osvdb.OpenReadOnly(root.Name(), aead)
}
