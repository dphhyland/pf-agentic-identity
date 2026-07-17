package pdp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The accounts API opens a customer file on first touch when the caller authenticates AS that
// customer. If this lookup ever sent a principal header, asking "does this subject hold this
// account?" would CREATE the subject, and the answer would always be yes. The absence of that
// header is load-bearing, so it is asserted rather than assumed.
func TestAccountsEntitlements_SendsNoPrincipal_SoTheLookupCannotProvision(t *testing.T) {
	var sawPrincipal string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPrincipal = r.Header.Get("X-Auth-Principal")
		w.Write([]byte(`{"accounts":[{"id":"CHK-1001","type":"checking","status":"open"}]}`))
	}))
	defer srv.Close()

	_, _, err := NewAccountsAPIEntitlements(srv.URL).RightsOn(context.Background(), "alice", "account", "CHK-1001")
	if err != nil {
		t.Fatalf("RightsOn: %v", err)
	}
	if sawPrincipal != "" {
		t.Fatalf("sent X-Auth-Principal=%q; a principal header makes the accounts API "+
			"self-provision an unknown customer, so the lookup must send none", sawPrincipal)
	}
}

func TestAccountsEntitlements_ClosedAccountIsNotHeld(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"accounts":[{"id":"SAV-1002","type":"savings","status":"closed"}]}`))
	}))
	defer srv.Close()

	rights, held, err := NewAccountsAPIEntitlements(srv.URL).RightsOn(context.Background(), "alice", "account", "SAV-1002")
	if err != nil {
		t.Fatalf("RightsOn: %v", err)
	}
	// The whole point of the intersection: a grant may still name this account.
	if held {
		t.Fatalf("closed account reported as held, with rights %v", rights)
	}
}

func TestAccountsEntitlements_OpenAccountIsHeld(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"accounts":[{"id":"CHK-1001","type":"checking","status":"open"}]}`))
	}))
	defer srv.Close()

	rights, held, err := NewAccountsAPIEntitlements(srv.URL).RightsOn(context.Background(), "alice", "account", "CHK-1001")
	if err != nil {
		t.Fatalf("RightsOn: %v", err)
	}
	if !held || len(rights) == 0 {
		t.Fatalf("own open account: held=%v rights=%v; want held with rights", held, rights)
	}
}

// An unknown customer is a real answer (they hold nothing), not a failure.
func TestAccountsEntitlements_UnknownCustomerHoldsNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"Unknown customer"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	_, held, err := NewAccountsAPIEntitlements(srv.URL).RightsOn(context.Background(), "nobody", "account", "CHK-1001")
	if err != nil {
		t.Fatalf("404 should not be an error: %v", err)
	}
	if held {
		t.Fatal("unknown customer reported as holding the account")
	}
}

// A lookup that FAILED must not read as "holds nothing": that would turn an outage of the
// system of record into a confident denial, and hide it.
func TestAccountsEntitlements_TransportFailureIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, _, err := NewAccountsAPIEntitlements(srv.URL).RightsOn(context.Background(), "alice", "account", "CHK-1001"); err == nil {
		t.Fatal("a 500 from the accounts API was swallowed; it must surface as an error")
	}
}

// The bank is the system of record for accounts and nothing else.
func TestAccountsEntitlements_OtherResourceTypesAreNotClaimed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not call the accounts API for a non-account resource type")
	}))
	defer srv.Close()

	_, held, err := NewAccountsAPIEntitlements(srv.URL).RightsOn(context.Background(), "alice", "payment", "pmt-1")
	if err != nil || held {
		t.Fatalf("payment resource: held=%v err=%v; want not-held, no error", held, err)
	}
}
