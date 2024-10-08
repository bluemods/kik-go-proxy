package utils

import (
	"encoding/json"
	"sync"
)

// Adapted from https://gist.github.com/bgadrian/cb8b9344d9c66571ef331a14eb7a2e80
// Supports generics and concurrent access from multiple goroutines.
type ConcurrentSet[K comparable] struct {
	_map       map[K]struct{} // empty structs occupy 0 memory
	sync.Mutex                // Mutex that allows for safe concurrent access
}

// Adds a key to the set.
// Returns true if the key is already present in the set.
func (s *ConcurrentSet[K]) Add(key K) bool {
	s.Lock()
	defer s.Unlock()
	_, found := s._map[key]
	if !found {
		// Add if not present
		s._map[key] = struct{}{}
	}
	return found
}

// Deletes a key from the set.
// If not present, this is a no-op.
func (s *ConcurrentSet[K]) Remove(key K) {
	s.Lock()
	defer s.Unlock()
	delete(s._map, key)
}

// Returns true if the set contains the key
func (s *ConcurrentSet[K]) Contains(key K) bool {
	s.Lock()
	defer s.Unlock()
	_, ok := s._map[key]
	return ok
}

// Clears the set.
// The set will be empty (size of 0) when this call returns.
func (s *ConcurrentSet[K]) Clear() {
	s.Lock()
	defer s.Unlock()
	clear(s._map)
}

// Returns the amount of items currently in the set.
func (s *ConcurrentSet[K]) Size() int {
	s.Lock()
	defer s.Unlock()
	return len(s._map)
}

// Returns true if the set is currently empty (has a size of 0)
func (s *ConcurrentSet[K]) IsEmpty() bool {
	s.Lock()
	defer s.Unlock()
	return len(s._map) == 0
}

// Returns all values in the set.
func (s *ConcurrentSet[K]) Values() []K {
	s.Lock()
	defer s.Unlock()
	v := make([]K, 0, len(s._map))
	for k := range s._map {
		v = append(v, k)
	}
	return v
}

// Create a new concurrent set.
func NewConcurrentSet[K comparable]() *ConcurrentSet[K] {
	return &ConcurrentSet[K]{_map: make(map[K]struct{})}
}

func (s *ConcurrentSet[K]) MarshalJSON() ([]byte, error) {
	s.Lock()
	defer s.Unlock()
	v := make([]K, 0, len(s._map))
	for k := range s._map {
		v = append(v, k)
	}
	return json.Marshal(v)
}

func (s *ConcurrentSet[K]) UnmarshalJSON(data []byte) error {
	s.Lock()
	defer s.Unlock()
	arr := &[]K{}
	if err := json.Unmarshal(data, arr); err != nil {
		return err
	}
	for _, v := range *arr {
		s._map[v] = struct{}{}
	}
	return nil
}
