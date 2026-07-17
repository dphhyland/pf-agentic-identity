package pdp

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPolicy mirrors policy/openbanking.yaml.
func testPolicy() *Policy {
	return &Policy{
		Name: "test-open-banking",
		Resources: map[string]ResourcePolicy{
			"account": {
				AuthorizationDetailsType: "account_information",
				IDPaths:                  []string{"locations", "data.accounts"},
			},
			"payment": {
				AuthorizationDetailsType: "payment_initiation",
				IDPaths:                  []string{"locations"},
			},
		},
		Actions: map[string]ActionPolicy{
			"read_balance":      {RequiresScope: "accounts.read"},
			"read_transactions": {RequiresScope: "accounts.read"},
			"initiate_payment":  {RequiresScope: "payments.write", MaxAmount: 1000},
		},
	}
}

// testEntitlements is what the subjects actually hold, independent of any grant.
// Alice is a view-only signatory on 444, which is what makes the gap between
// consent and entitlement visible.
func testEntitlements() *StaticEntitlements {
	return &StaticEntitlements{subjects: map[string]HoldingsByType{
		"alice": {
			"account": {
				"111": {"read_balance", "read_transactions", "initiate_payment"},
				"222": {"read_balance", "read_transactions"},
				"333": {"read_balance"},
				"444": {"read_balance"},
			},
			"payment": {"pmt-1": {"initiate_payment"}},
		},
	}}
}

// failingEntitlements stands in for an unreachable system of record.
type failingEntitlements struct{}

func (failingEntitlements) RightsOn(context.Context, string, string, string) ([]string, bool, error) {
	return nil, false, errors.New("directory unreachable")
}
func (failingEntitlements) Holdings(context.Context, string) HoldingsByType { return nil }

// consentContext builds the AuthZEN context the GM API sends: the grant's
// scopes and authorization_details, plus the oauth coordinates.
func consentContext(scopes []string, details ...map[string]any) map[string]any {
	asAny := make([]any, 0, len(details))
	for _, d := range details {
		asAny = append(asAny, d)
	}
	scopesAny := make([]any, 0, len(scopes))
	for _, s := range scopes {
		scopesAny = append(scopesAny, s)
	}
	return map[string]any{
		"oauth":                 map[string]any{"client_id": "acme-budgeting", "grant_id": "grant-123"},
		"scopes":                scopesAny,
		"authorization_details": asAny,
	}
}

// accountConsent is a consent over two named accounts.
func accountConsent() map[string]any {
	return map[string]any{
		"type":      "account_information",
		"actions":   []any{"read_balance", "read_transactions"},
		"locations": []any{"111", "222"},
	}
}

func evaluate(t *testing.T, req *EvaluationRequest) *EvaluationResponse {
	t.Helper()
	resp := NewEngine(testPolicy(), testEntitlements()).Evaluate(context.Background(), req)
	require.NotNil(t, resp, "engine must always return a response")
	require.NotNil(t, resp.Context, "every decision must carry a context")
	return resp
}

func TestEvaluate_PermitsConsentedAccountAndAction(t *testing.T) {
	resp := evaluate(t, &EvaluationRequest{
		Subject:  Entity{Type: "user", ID: "alice"},
		Action:   Action{Name: "read_balance"},
		Resource: Entity{Type: "account", ID: "111"},
		Context:  consentContext([]string{"accounts.read"}, accountConsent()),
	})

	assert.True(t, resp.Decision, "an account named in the consent should be readable")
	assert.Equal(t, ReasonPermitted, resp.Context.ID)
	assert.NotEmpty(t, resp.Context.ReasonUser["en"])
}

func TestEvaluate_DeniesAccountOutsideConsent(t *testing.T) {
	resp := evaluate(t, &EvaluationRequest{
		Subject:  Entity{Type: "user", ID: "alice"},
		Action:   Action{Name: "read_balance"},
		Resource: Entity{Type: "account", ID: "999"}, // not consented
		Context:  consentContext([]string{"accounts.read"}, accountConsent()),
	})

	assert.False(t, resp.Decision, "an account absent from the consent must be denied")
	assert.Equal(t, ReasonResourceNotConsented, resp.Context.ID)
}

func TestEvaluate_DeniesActionOutsideConsent(t *testing.T) {
	// The consent covers reads only; the grant also carries payments.write, so
	// this must fail on the consent rather than on scope.
	resp := evaluate(t, &EvaluationRequest{
		Subject:  Entity{Type: "user", ID: "alice"},
		Action:   Action{Name: "initiate_payment"},
		Resource: Entity{Type: "account", ID: "111"},
		Context: consentContext([]string{"accounts.read", "payments.write"},
			accountConsent()),
	})

	assert.False(t, resp.Decision)
	assert.Equal(t, ReasonActionNotConsented, resp.Context.ID)
}

func TestEvaluate_DeniesWhenScopeMissing(t *testing.T) {
	resp := evaluate(t, &EvaluationRequest{
		Subject:  Entity{Type: "user", ID: "alice"},
		Action:   Action{Name: "read_balance"},
		Resource: Entity{Type: "account", ID: "111"},
		Context:  consentContext([]string{"openid"}, accountConsent()), // no accounts.read
	})

	assert.False(t, resp.Decision)
	assert.Equal(t, ReasonMissingScope, resp.Context.ID)
}

func TestEvaluate_DeniesWhenNoConsentOfGoverningType(t *testing.T) {
	resp := evaluate(t, &EvaluationRequest{
		Subject:  Entity{Type: "user", ID: "alice"},
		Action:   Action{Name: "read_balance"},
		Resource: Entity{Type: "account", ID: "111"},
		Context:  consentContext([]string{"accounts.read"}), // no authorization_details at all
	})

	assert.False(t, resp.Decision)
	assert.Equal(t, ReasonNoConsentForType, resp.Context.ID)
}

func TestEvaluate_DeniesUnknownResourceTypeAndAction(t *testing.T) {
	base := func() *EvaluationRequest {
		return &EvaluationRequest{
			Subject:  Entity{Type: "user", ID: "alice"},
			Action:   Action{Name: "read_balance"},
			Resource: Entity{Type: "account", ID: "111"},
			Context:  consentContext([]string{"accounts.read"}, accountConsent()),
		}
	}

	t.Run("unknown resource type", func(t *testing.T) {
		req := base()
		req.Resource.Type = "spaceship"
		resp := evaluate(t, req)
		assert.False(t, resp.Decision)
		assert.Equal(t, ReasonUnknownResourceType, resp.Context.ID)
	})

	t.Run("unknown action", func(t *testing.T) {
		req := base()
		req.Action.Name = "launch"
		resp := evaluate(t, req)
		assert.False(t, resp.Decision)
		assert.Equal(t, ReasonUnknownAction, resp.Context.ID)
	})
}

func TestEvaluate_DeniesWithoutResourceID(t *testing.T) {
	resp := evaluate(t, &EvaluationRequest{
		Subject:  Entity{Type: "user", ID: "alice"},
		Action:   Action{Name: "read_balance"},
		Resource: Entity{Type: "account"}, // no id
		Context:  consentContext([]string{"accounts.read"}, accountConsent()),
	})

	assert.False(t, resp.Decision)
	assert.Equal(t, ReasonMissingResourceID, resp.Context.ID)
}

func TestEvaluate_EnforcesConsentedAmountLimit(t *testing.T) {
	paymentConsent := map[string]any{
		"type":      "payment_initiation",
		"actions":   []any{"initiate_payment"},
		"locations": []any{"pmt-1"},
	}
	request := func(amount float64) *EvaluationRequest {
		return &EvaluationRequest{
			Subject:  Entity{Type: "user", ID: "alice"},
			Action:   Action{Name: "initiate_payment", Properties: map[string]any{"amount": amount}},
			Resource: Entity{Type: "payment", ID: "pmt-1"},
			Context:  consentContext([]string{"payments.write"}, paymentConsent),
		}
	}

	t.Run("under the limit", func(t *testing.T) {
		resp := evaluate(t, request(999))
		assert.True(t, resp.Decision)
	})

	t.Run("over the limit", func(t *testing.T) {
		resp := evaluate(t, request(1001))
		assert.False(t, resp.Decision)
		assert.Equal(t, ReasonAmountExceedsLimit, resp.Context.ID)
	})
}

// The consented account ids may be carried under data rather than as RAR
// locations; the policy names both paths.
func TestEvaluate_ReadsConsentedIDsFromDataPath(t *testing.T) {
	consent := map[string]any{
		"type":    "account_information",
		"actions": []any{"read_balance"},
		"data":    map[string]any{"accounts": []any{"333"}},
	}
	resp := evaluate(t, &EvaluationRequest{
		Subject:  Entity{Type: "user", ID: "alice"},
		Action:   Action{Name: "read_balance"},
		Resource: Entity{Type: "account", ID: "333"},
		Context:  consentContext([]string{"accounts.read"}, consent),
	})

	assert.True(t, resp.Decision, "data.accounts should be honoured as an id path")
}

// A consent that names no actions constrains only which resources are shared.
func TestEvaluate_ConsentWithoutActionsPermitsAnyPolicyAction(t *testing.T) {
	consent := map[string]any{
		"type":      "account_information",
		"locations": []any{"111"},
	}
	resp := evaluate(t, &EvaluationRequest{
		Subject:  Entity{Type: "user", ID: "alice"},
		Action:   Action{Name: "read_transactions"},
		Resource: Entity{Type: "account", ID: "111"},
		Context:  consentContext([]string{"accounts.read"}, consent),
	})

	assert.True(t, resp.Decision)
}

// A denial must explain itself to the user without leaking policy internals,
// which the GM API relies on when it forwards reasons to the client.
func TestEvaluate_DenialSeparatesUserAndAdminReasons(t *testing.T) {
	resp := evaluate(t, &EvaluationRequest{
		Subject:  Entity{Type: "user", ID: "alice"},
		Action:   Action{Name: "read_balance"},
		Resource: Entity{Type: "account", ID: "999"},
		Context:  consentContext([]string{"accounts.read"}, accountConsent()),
	})

	require.False(t, resp.Decision)
	assert.NotEmpty(t, resp.Context.ReasonUser["en"], "a denial must give the user a reason")
	assert.NotEmpty(t, resp.Context.ReasonAdmin["en"], "a denial must give operators detail")
	assert.NotContains(t, resp.Context.ReasonUser["en"], "grant-123",
		"the user-facing reason must not name internal grant detail")
}

func TestEvaluate_MissingContextDeniesRatherThanPermits(t *testing.T) {
	resp := evaluate(t, &EvaluationRequest{
		Subject:  Entity{Type: "user", ID: "alice"},
		Action:   Action{Name: "read_balance"},
		Resource: Entity{Type: "account", ID: "111"},
		Context:  nil, // no grant constraints at all
	})

	// It fails at the first gate it cannot pass: with no context there are no
	// scopes either. Which gate catches it matters less than that one does.
	assert.False(t, resp.Decision, "absent grant constraints must not permit")
	assert.Equal(t, ReasonMissingScope, resp.Context.ID)
}

// PingFederate renders scopes as objects; the PDP accepts that alongside plain
// strings and a space-separated string.
func TestParseConstraints_AcceptsEveryScopeShape(t *testing.T) {
	shapes := map[string]any{
		"array of strings":     []any{"accounts.read", "payments.write"},
		"space-separated":      "accounts.read payments.write",
		"pingfederate objects": []any{map[string]any{"scope": "accounts.read"}, map[string]any{"scope": "payments.write"}},
	}

	for name, scopes := range shapes {
		t.Run(name, func(t *testing.T) {
			got, err := parseConstraints(map[string]any{"scopes": scopes})
			require.NoError(t, err)
			assert.Equal(t, []string{"accounts.read", "payments.write"}, []string(got.Scopes))
		})
	}
}

func TestEvaluateBatch_AppliesDefaultsAndPreservesOrder(t *testing.T) {
	subject := Entity{Type: "user", ID: "alice"}
	ctx := consentContext([]string{"accounts.read"}, accountConsent())

	resp := NewEngine(testPolicy(), testEntitlements()).EvaluateBatch(context.Background(), &EvaluationsRequest{
		Subject: &subject,
		Action:  &Action{Name: "read_balance"},
		Context: ctx,
		Evaluations: []EvaluationRequest{
			{Resource: Entity{Type: "account", ID: "111"}}, // consented
			{Resource: Entity{Type: "account", ID: "999"}}, // not consented
			{Resource: Entity{Type: "account", ID: "222"}}, // consented
		},
	})

	require.Len(t, resp.Evaluations, 3)
	assert.True(t, resp.Evaluations[0].Decision)
	assert.False(t, resp.Evaluations[1].Decision)
	assert.True(t, resp.Evaluations[2].Decision)
}

// ---- where the grant and the entitlement disagree ----
//
// These are the cases a token introspection cannot see: the grant is valid,
// unexpired and covers the request, and the answer is still no.

// Alice consented to share 555 and then stopped holding it. The consent still
// names it; the authority behind it is gone.
func TestEvaluate_DeniesWhenSubjectNoLongerHoldsConsentedResource(t *testing.T) {
	consent := map[string]any{
		"type":      "account_information",
		"actions":   []any{"read_balance"},
		"locations": []any{"111", "555"}, // 555 is consented but not held
	}
	resp := evaluate(t, &EvaluationRequest{
		Subject:  Entity{Type: "user", ID: "alice"},
		Action:   Action{Name: "read_balance"},
		Resource: Entity{Type: "account", ID: "555"},
		Context:  consentContext([]string{"accounts.read"}, consent),
	})

	assert.False(t, resp.Decision, "a consent cannot outlive the access it was consent to")
	assert.Equal(t, ReasonSubjectNotEntitled, resp.Context.ID)
}

// Alice is a view-only signatory on 444. A consent to read transactions on it
// was never worth more than her own rights over it.
func TestEvaluate_DeniesWhenEntitlementLacksTheConsentedRight(t *testing.T) {
	consent := map[string]any{
		"type":      "account_information",
		"actions":   []any{"read_balance", "read_transactions"},
		"locations": []any{"444"},
	}
	ctx := consentContext([]string{"accounts.read"}, consent)

	t.Run("right she holds", func(t *testing.T) {
		resp := evaluate(t, &EvaluationRequest{
			Subject:  Entity{Type: "user", ID: "alice"},
			Action:   Action{Name: "read_balance"},
			Resource: Entity{Type: "account", ID: "444"},
			Context:  ctx,
		})
		assert.True(t, resp.Decision)
	})

	t.Run("right she does not", func(t *testing.T) {
		resp := evaluate(t, &EvaluationRequest{
			Subject:  Entity{Type: "user", ID: "alice"},
			Action:   Action{Name: "read_transactions"},
			Resource: Entity{Type: "account", ID: "444"},
			Context:  ctx,
		})
		assert.False(t, resp.Decision, "the grant cannot widen what the subject holds")
		assert.Equal(t, ReasonEntitlementLacksRight, resp.Context.ID)
	})
}

// The privacy ordering: a client asking about a resource it was never granted
// must learn only that, never anything about what the subject holds. Otherwise
// this endpoint becomes an oracle for enumerating a subject's accounts.
func TestEvaluate_ConsentIsCheckedBeforeEntitlement(t *testing.T) {
	resp := evaluate(t, &EvaluationRequest{
		Subject: Entity{Type: "user", ID: "alice"},
		Action:  Action{Name: "read_balance"},
		// Alice does hold 333, but this consent does not name it.
		Resource: Entity{Type: "account", ID: "333"},
		Context:  consentContext([]string{"accounts.read"}, accountConsent()),
	})

	require.False(t, resp.Decision)
	assert.Equal(t, ReasonResourceNotConsented, resp.Context.ID,
		"a resource outside the consent must fail on consent, revealing nothing about entitlement")
	assert.NotContains(t, resp.Context.ReasonUser["en"], "no longer",
		"the user-facing reason must not hint at what the subject holds")
}

// An unreachable system of record must not fall back to trusting the grant.
func TestEvaluate_DeniesWhenEntitlementLookupFails(t *testing.T) {
	resp := NewEngine(testPolicy(), failingEntitlements{}).Evaluate(context.Background(), &EvaluationRequest{
		Subject:  Entity{Type: "user", ID: "alice"},
		Action:   Action{Name: "read_balance"},
		Resource: Entity{Type: "account", ID: "111"},
		Context:  consentContext([]string{"accounts.read"}, accountConsent()),
	})

	require.False(t, resp.Decision, "an unverifiable entitlement must not permit")
	assert.Equal(t, ReasonEntitlementUnavailable, resp.Context.ID)
	assert.NotContains(t, resp.Context.ReasonUser["en"], "unreachable",
		"the user-facing reason must not leak infrastructure detail")
}

// A PDP with no view of the system of record denies everything.
func TestNewEngine_NilEntitlementSourceDeniesEverything(t *testing.T) {
	resp := NewEngine(testPolicy(), nil).Evaluate(context.Background(), &EvaluationRequest{
		Subject:  Entity{Type: "user", ID: "alice"},
		Action:   Action{Name: "read_balance"},
		Resource: Entity{Type: "account", ID: "111"},
		Context:  consentContext([]string{"accounts.read"}, accountConsent()),
	})

	require.False(t, resp.Decision)
	assert.Equal(t, ReasonSubjectNotEntitled, resp.Context.ID)
}

func TestLoadEntitlements_ReadsShippedDemoEntitlements(t *testing.T) {
	e, err := LoadEntitlements("../policy/entitlements.yaml")
	require.NoError(t, err, "the shipped demo entitlements must parse")

	rights, held, err := e.RightsOn(context.Background(), "alice", "account", "444")
	require.NoError(t, err)
	require.True(t, held, "alice should hold the business account")
	assert.Equal(t, []string{"read_balance"}, rights, "as a view-only signatory")

	_, held, err = e.RightsOn(context.Background(), "alice", "account", "222")
	require.NoError(t, err)
	assert.False(t, held, "alice should no longer hold 222, though she consented to share it")
}

func TestLoadPolicy_ReadsShippedDemoPolicy(t *testing.T) {
	p, err := LoadPolicy("../policy/openbanking.yaml")
	require.NoError(t, err, "the shipped demo policy must parse")

	assert.Equal(t, "open-banking-consent", p.Name)
	assert.Equal(t, "account_information", p.Resources["account"].AuthorizationDetailsType)
	assert.Equal(t, "accounts.read", p.Actions["read_balance"].RequiresScope)
	assert.Equal(t, float64(1000), p.Actions["initiate_payment"].MaxAmount)
}
