package utils

import (
	"sync"
)

// Adapted from https://gist.github.com/bgadrian/cb8b9344d9c66571ef331a14eb7a2e80
// Supports generics and concurrent access from multiple goroutines.
type ConcurrentSet[T comparable] struct {
	_map       map[T]struct{} // empty structs occupy 0 memory
	sync.Mutex                // Mutex that allows for safe concurrent access
}

// Adds a key to the set.
// Returns true if the key was added to the set,
// Returns false if the key is already in the set.
func (s *ConcurrentSet[T]) Add(key T) bool {
	s.Lock()
	defer s.Unlock()
	_, ok := s._map[key]
	if !ok {
		// Add if not present
		s._map[key] = struct{}{}
	}
	return ok
}

// Deletes a key from the set.
// If not present, this is a no-op.
func (s *ConcurrentSet[T]) Remove(key T) {
	s.Lock()
	defer s.Unlock()
	delete(s._map, key)
}

// Returns true if the set contains the key
func (s *ConcurrentSet[T]) Contains(key T) bool {
	s.Lock()
	defer s.Unlock()
	_, ok := s._map[key]
	return ok
}

// Clears the set.
// The set will be empty (size of 0) when this call returns.
func (s *ConcurrentSet[T]) Clear() {
	s.Lock()
	defer s.Unlock()
	clear(s._map)
}

// Returns the amount of items currently in the set.
func (s *ConcurrentSet[T]) Size() int {
	s.Lock()
	defer s.Unlock()
	return len(s._map)
}

// Returns true if the set is currently empty (has a size of 0)
func (s *ConcurrentSet[T]) IsEmpty() bool {
	return s.Size() == 0
}

// Create a new concurrent set.
func NewConcurrentSet[T comparable]() *ConcurrentSet[T] {
	return &ConcurrentSet[T]{_map: make(map[T]struct{})}
}
