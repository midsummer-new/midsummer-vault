package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMetaRoundTrip(t *testing.T) {
	s := testStore(t)

	meta := MetaStore{
		"STRIPE_KEY": {
			Description:     "Stripe live key",
			RotateEveryDays: 90,
			CreatedAt:       "2026-01-01T00:00:00Z",
		},
	}

	if err := s.SaveMeta(meta); err != nil {
		t.Fatalf("SaveMeta: %v", err)
	}

	loaded, err := s.LoadMeta()
	if err != nil {
		t.Fatalf("LoadMeta: %v", err)
	}

	m, ok := loaded["STRIPE_KEY"]
	if !ok {
		t.Fatal("expected STRIPE_KEY in meta")
	}
	if m.Description != "Stripe live key" {
		t.Fatalf("description = %q, want 'Stripe live key'", m.Description)
	}
	if m.RotateEveryDays != 90 {
		t.Fatalf("rotate_every_days = %d, want 90", m.RotateEveryDays)
	}
}

func TestMetaLoadEmpty(t *testing.T) {
	s := testStore(t)

	meta, err := s.LoadMeta()
	if err != nil {
		t.Fatalf("LoadMeta on empty: %v", err)
	}
	if len(meta) != 0 {
		t.Fatalf("expected empty meta, got %d entries", len(meta))
	}
}

func TestSetMeta(t *testing.T) {
	s := testStore(t)

	err := s.SetMeta("DB_URL", func(m *SecretMeta) {
		m.Description = "Production database"
	})
	if err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	m, err := s.GetMeta("DB_URL")
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if m == nil || m.Description != "Production database" {
		t.Fatalf("expected 'Production database', got %v", m)
	}
}

func TestDeleteMeta(t *testing.T) {
	s := testStore(t)

	s.SetMeta("KEY", func(m *SecretMeta) {
		m.Description = "test"
	})

	if err := s.DeleteMeta("KEY"); err != nil {
		t.Fatalf("DeleteMeta: %v", err)
	}

	m, _ := s.GetMeta("KEY")
	if m != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestRenameMeta(t *testing.T) {
	s := testStore(t)

	s.SetMeta("OLD", func(m *SecretMeta) {
		m.Description = "desc"
		m.RotateEveryDays = 30
	})

	if err := s.RenameMeta("OLD", "NEW"); err != nil {
		t.Fatalf("RenameMeta: %v", err)
	}

	old, _ := s.GetMeta("OLD")
	if old != nil {
		t.Fatal("OLD should be gone after rename")
	}

	newMeta, _ := s.GetMeta("NEW")
	if newMeta == nil || newMeta.Description != "desc" {
		t.Fatal("NEW should have OLD's metadata")
	}
}

func TestRenameMetaNoOp(t *testing.T) {
	s := testStore(t)

	// renaming a key with no metadata should be a no-op
	if err := s.RenameMeta("NONEXISTENT", "NEW"); err != nil {
		t.Fatalf("RenameMeta no-op: %v", err)
	}
}

func TestRotationInfoOverdue(t *testing.T) {
	m := &SecretMeta{
		RotateEveryDays: 30,
		LastRotatedAt:   time.Now().AddDate(0, 0, -45).UTC().Format(time.RFC3339),
	}

	status, days := m.RotationInfo()
	if status != RotationOverdue {
		t.Fatalf("expected overdue, got %d", status)
	}
	if days >= 0 {
		t.Fatalf("expected negative days, got %d", days)
	}
}

func TestRotationInfoOK(t *testing.T) {
	m := &SecretMeta{
		RotateEveryDays: 90,
		LastRotatedAt:   time.Now().AddDate(0, 0, -10).UTC().Format(time.RFC3339),
	}

	status, days := m.RotationInfo()
	if status != RotationOK {
		t.Fatalf("expected OK, got %d", status)
	}
	if days <= 14 {
		t.Fatalf("expected >14 days, got %d", days)
	}
}

func TestRotationInfoDueSoon(t *testing.T) {
	m := &SecretMeta{
		RotateEveryDays: 30,
		LastRotatedAt:   time.Now().AddDate(0, 0, -25).UTC().Format(time.RFC3339),
	}

	status, days := m.RotationInfo()
	if status != RotationDueSoon {
		t.Fatalf("expected DueSoon, got %d", status)
	}
	if days < 0 || days > 14 {
		t.Fatalf("expected 0-14 days, got %d", days)
	}
}

func TestRotationInfoNone(t *testing.T) {
	m := &SecretMeta{
		Description: "no rotation set",
	}

	status, _ := m.RotationInfo()
	if status != RotationNone {
		t.Fatalf("expected None, got %d", status)
	}

	// nil meta
	status, _ = (*SecretMeta)(nil).RotationInfo()
	if status != RotationNone {
		t.Fatalf("expected None for nil, got %d", status)
	}
}

func TestMetaFileWrittenToCorrectPath(t *testing.T) {
	s := testStore(t)

	s.SetMeta("KEY", func(m *SecretMeta) {
		m.Description = "test"
	})

	path := filepath.Join(s.dir, "meta.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("meta.json should exist at %s", path)
	}
}
