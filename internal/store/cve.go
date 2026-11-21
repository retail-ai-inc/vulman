package store

import "vulman/internal/cvedb"

// OpenCVEDatabase reuses the workspace's AEAD without exposing key material to
// the desktop bridge. The catalogue owns its own bbolt handle and file lock.
func (s *Store) OpenCVEDatabase() (*cvedb.Store, error) {
	return cvedb.Open(s.root.Name(), s.aead)
}
