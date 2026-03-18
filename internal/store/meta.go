package store

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
)

const metaFile = "meta.json"

// SecretMeta holds non-secret metadata for a single key.
// Stored in plaintext — no secret values here.
type SecretMeta struct {
	Description     string `json:"description,omitempty"`
	RotateEveryDays int    `json:"rotate_every_days,omitempty"`
	LastRotatedAt   string `json:"last_rotated_at,omitempty"` // ISO 8601
	CreatedAt       string `json:"created_at,omitempty"`
}

// MetaStore is the full contents of .vault/meta.json keyed by secret name.
type MetaStore map[string]*SecretMeta

// LoadMeta reads .vault/meta.json, returning an empty map if it doesn't exist.
func (s *Store) LoadMeta() (MetaStore, error) {
	path := filepath.Join(s.dir, metaFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return MetaStore{}, nil
		}
		return nil, fmt.Errorf("read meta: %w", err)
	}

	var meta MetaStore
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse meta: %w", err)
	}
	return meta, nil
}

// SaveMeta writes the metadata map to .vault/meta.json.
func (s *Store) SaveMeta(meta MetaStore) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	path := filepath.Join(s.dir, metaFile)
	return os.WriteFile(path, append(data, '\n'), 0644)
}

// SetMeta updates metadata for a single key, creating it if needed.
func (s *Store) SetMeta(name string, update func(m *SecretMeta)) error {
	meta, err := s.LoadMeta()
	if err != nil {
		return err
	}
	if meta[name] == nil {
		meta[name] = &SecretMeta{}
	}
	update(meta[name])
	return s.SaveMeta(meta)
}

// GetMeta returns metadata for a single key, or nil if none exists.
func (s *Store) GetMeta(name string) (*SecretMeta, error) {
	meta, err := s.LoadMeta()
	if err != nil {
		return nil, err
	}
	return meta[name], nil
}

// DeleteMeta removes metadata for a key.
func (s *Store) DeleteMeta(name string) error {
	meta, err := s.LoadMeta()
	if err != nil {
		return err
	}
	delete(meta, name)
	return s.SaveMeta(meta)
}

// RenameMeta moves metadata from oldName to newName.
func (s *Store) RenameMeta(oldName, newName string) error {
	meta, err := s.LoadMeta()
	if err != nil {
		return err
	}
	if m, ok := meta[oldName]; ok {
		meta[newName] = m
		delete(meta, oldName)
		return s.SaveMeta(meta)
	}
	return nil // no metadata to move
}

// RotationStatus describes whether a secret needs rotation.
type RotationStatus int

const (
	RotationNone    RotationStatus = iota // no rotation policy
	RotationOK                            // rotated recently
	RotationDueSoon                       // due within 14 days
	RotationOverdue                       // past due
)

// RotationInfo returns the rotation status and days until/past due.
// Positive days = due in N days. Negative = overdue by N days.
func (m *SecretMeta) RotationInfo() (RotationStatus, int) {
	if m == nil || m.RotateEveryDays <= 0 {
		return RotationNone, 0
	}

	lastRotated := m.LastRotatedAt
	if lastRotated == "" {
		lastRotated = m.CreatedAt
	}
	if lastRotated == "" {
		return RotationOverdue, 0 // no date info at all, assume overdue
	}

	t, err := time.Parse(time.RFC3339, lastRotated)
	if err != nil {
		return RotationOverdue, 0
	}

	nextRotation := t.AddDate(0, 0, m.RotateEveryDays)
	daysUntil := int(math.Ceil(time.Until(nextRotation).Hours() / 24))

	switch {
	case daysUntil < 0:
		return RotationOverdue, daysUntil
	case daysUntil <= 14:
		return RotationDueSoon, daysUntil
	default:
		return RotationOK, daysUntil
	}
}

// NowISO returns the current time in ISO 8601 / RFC 3339 format.
func NowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}
