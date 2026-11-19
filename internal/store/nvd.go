package store

import "vulman/internal/nvddb"

func (s *Store) OpenNVDDatabase() (*nvddb.Store, error) {
	return nvddb.Open(s.root.Name(), s.aead)
}
