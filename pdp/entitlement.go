package pdp

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Effective access is the intersection of two independent authorities:
//
//	what the client was granted   (scopes + RFC 9396 authorization_details)
//	∩ what the subject holds      (entitlement, from the system of record)
//
// The grant cannot manufacture authority the subject never had. Alice consenting
// to share an account she has since closed does not resurrect her access to it,
// and a consent to initiate payments on an account she only has view rights over
// was never worth anything. Checking only the grant -- which is what a token
// introspection tells you -- misses both cases.
//
// The two halves reach the PDP by different routes, and that asymmetry is the
// point. The GM API asserts the grant in the request context because it owns the
// grant. It does not assert the entitlement, because it is not the authority on
// what the subject holds; if it were, a grant could simply claim entitlement it
// never had. So the PDP looks entitlement up itself, from whoever does own it.

// EntitlementSource is the PDP's window onto the system of record. In a real
// deployment this reads PingDirectory, or the core banking system, or whatever
// holds the truth about who may touch what.
type EntitlementSource interface {
	// RightsOn returns the rights a subject holds over one resource, and
	// whether the subject holds that resource at all. The two are distinct:
	// holding nothing is "you have no access to this account", while holding
	// the resource without the right is "your access does not go that far".
	RightsOn(ctx context.Context, subject, resourceType, resourceID string) (rights []string, held bool, err error)

	// Holdings returns everything a subject holds, keyed by resource type then
	// resource id. It exists for the demo UI; a production PDP would not offer
	// this, because nothing should be able to enumerate a subject's holdings.
	Holdings(ctx context.Context, subject string) HoldingsByType
}

// RightsByResourceID maps a resource id to the rights held over it.
type RightsByResourceID map[string][]string

// HoldingsByType maps a resource type to the resources held of that type.
type HoldingsByType map[string]RightsByResourceID

// StaticEntitlements is a file-backed EntitlementSource for the demo.
type StaticEntitlements struct {
	subjects map[string]HoldingsByType
}

type entitlementFile struct {
	Subjects map[string]HoldingsByType `yaml:"subjects"`
}

// LoadEntitlements reads an entitlement file.
func LoadEntitlements(path string) (*StaticEntitlements, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read entitlements: %w", err)
	}
	var f entitlementFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse entitlements %s: %w", path, err)
	}
	if len(f.Subjects) == 0 {
		return nil, fmt.Errorf("entitlements %s lists no subjects, so every request would be denied", path)
	}
	return &StaticEntitlements{subjects: f.Subjects}, nil
}

func (s *StaticEntitlements) RightsOn(_ context.Context, subject, resourceType, resourceID string) ([]string, bool, error) {
	byType, ok := s.subjects[subject]
	if !ok {
		return nil, false, nil
	}
	byID, ok := byType[resourceType]
	if !ok {
		return nil, false, nil
	}
	rights, ok := byID[resourceID]
	if !ok {
		return nil, false, nil
	}
	return rights, true, nil
}

func (s *StaticEntitlements) Holdings(_ context.Context, subject string) HoldingsByType {
	return s.subjects[subject]
}

// NoEntitlements is an EntitlementSource that holds nothing.
//
// It denies every request, which is the correct default: a PDP with no view of
// the system of record cannot confirm the subject holds anything, and must not
// fall back to trusting the grant alone.
type NoEntitlements struct{}

func (NoEntitlements) RightsOn(context.Context, string, string, string) ([]string, bool, error) {
	return nil, false, nil
}

func (NoEntitlements) Holdings(context.Context, string) HoldingsByType { return nil }
