package pdp

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy is the rule set this PDP decides against.
//
// The vocabulary is deliberately small and fixed rather than a general policy
// language: the point of the demo is that the *grant* carries the authority and
// the PDP just checks requests against it, so the policy only has to say how a
// resource type maps onto the grant's authorization_details and what each action
// costs in scope. Anything richer belongs in a real PDP.
type Policy struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	// Resources maps an AuthZEN resource type onto the part of the grant that
	// governs it. A resource type absent here is denied.
	Resources map[string]ResourcePolicy `yaml:"resources"`

	// Actions are the operations the policy knows about. An action absent here
	// is denied, so the set of keys is the PDP's whole action vocabulary.
	Actions map[string]ActionPolicy `yaml:"actions"`
}

// ResourcePolicy ties a resource type to the grant constraints that govern it.
type ResourcePolicy struct {
	// AuthorizationDetailsType is the RFC 9396 authorization_details "type"
	// that carries consent for this resource type.
	AuthorizationDetailsType string `yaml:"authorization_details_type"`

	// IDPaths lists where, inside a matching authorization detail, the consented
	// resource identifiers appear. "locations" reads the RAR locations array;
	// a dotted path like "data.accounts" reads that field out of data.
	// The first path that yields any identifiers wins.
	IDPaths []string `yaml:"id_paths"`
}

// ActionPolicy is what an action requires before it is permitted.
type ActionPolicy struct {
	// RequiresScope must be present in the grant's scopes. Empty means the
	// action needs no particular scope.
	RequiresScope string `yaml:"requires_scope"`

	// MaxAmount, when non-zero, caps the "amount" action property. It models
	// the kind of contextual limit a consent carries in open banking.
	MaxAmount float64 `yaml:"max_amount"`
}

// LoadPolicy reads a policy from a YAML file.
func LoadPolicy(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", path, err)
	}
	if len(p.Resources) == 0 || len(p.Actions) == 0 {
		return nil, fmt.Errorf("policy %s defines no resources or no actions, so it would deny everything", path)
	}
	return &p, nil
}

// grantConstraints is the slice of the grant that the GM API passes down in the
// AuthZEN request context. It is the authority the PDP decides against.
type grantConstraints struct {
	ClientID string
	GrantID  string
	Scopes   []string
	Details  []authorizationDetail
}

// authorizationDetail is an RFC 9396 authorization_details entry.
type authorizationDetail struct {
	Type       string         `json:"type"`
	Actions    []string       `json:"actions,omitempty"`
	Locations  []string       `json:"locations,omitempty"`
	Identifier string         `json:"identifier,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
}

// scopeList tolerates the several shapes a scope collection arrives in: a
// space-separated string, an array of strings, or an array of
// {"scope": "..."} objects as PingFederate returns them.
type scopeList []string

func (s *scopeList) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		*s = strings.Fields(str)
		return nil
	}

	var items []json.RawMessage
	if err := json.Unmarshal(b, &items); err != nil {
		return fmt.Errorf("scopes must be a string or an array: %w", err)
	}

	out := make(scopeList, 0, len(items))
	for _, item := range items {
		var str string
		if err := json.Unmarshal(item, &str); err == nil {
			out = append(out, str)
			continue
		}
		var obj struct {
			Scope string `json:"scope"`
		}
		if err := json.Unmarshal(item, &obj); err == nil && obj.Scope != "" {
			out = append(out, obj.Scope)
		}
	}
	*s = out
	return nil
}

// parseConstraints pulls the grant constraints out of the AuthZEN context.
// It round-trips through JSON so the polymorphic scope shapes above are handled
// by the same decoder that handles them on the wire.
func parseConstraints(ctx map[string]any) (*grantConstraints, error) {
	if ctx == nil {
		return &grantConstraints{}, nil
	}

	var raw struct {
		OAuth struct {
			ClientID string `json:"client_id"`
			GrantID  string `json:"grant_id"`
		} `json:"oauth"`
		Scopes               scopeList             `json:"scopes"`
		AuthorizationDetails []authorizationDetail `json:"authorization_details"`
	}

	b, err := json.Marshal(ctx)
	if err != nil {
		return nil, fmt.Errorf("re-encode context: %w", err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("decode grant constraints from context: %w", err)
	}

	return &grantConstraints{
		ClientID: raw.OAuth.ClientID,
		GrantID:  raw.OAuth.GrantID,
		Scopes:   raw.Scopes,
		Details:  raw.AuthorizationDetails,
	}, nil
}

// consentedIDs returns the resource identifiers named by an authorization
// detail at the given path. "locations" reads the RAR locations array; a dotted
// path such as "data.accounts" reads that field out of data.
func (d authorizationDetail) consentedIDs(path string) []string {
	if path == "locations" {
		return d.Locations
	}

	rest, ok := strings.CutPrefix(path, "data.")
	if !ok {
		return nil
	}
	return toStrings(d.Data[rest])
}

// toStrings coerces a JSON value into a string slice, accepting either a lone
// string or an array of them.
func toStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
