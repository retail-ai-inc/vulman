package store

import "vulman/internal/osvdb"

func (s *Store) OpenOSVDatabase() (*osvdb.Store, error) {
	return osvdb.Open(s.root.Name(), s.aead)
}
