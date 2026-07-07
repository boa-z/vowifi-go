package swu

import (
	"bytes"
	"testing"

	"github.com/boa-z/vowifi-go/engine/swu/eapaka"
)

func TestEAPReauthenticationStateApplyUpdateAcceptsNextIdentityAndPseudonym(t *testing.T) {
	initialKeys := testEAPReauthKeys(0x01)
	nextKeys := testEAPReauthKeys(0x10)
	state := EAPReauthenticationState{
		Identity:            " reauth-old ",
		NextPseudonym:       " pseudo-old ",
		Counter:             2,
		CounterOK:           true,
		Keys:                initialKeys,
		LastAcceptedCounter: 2,
		LastRejectedCounter: 1,
	}

	updated, ok := state.ApplyUpdate(EAPReauthenticationUpdate{
		NextReauthID:    " reauth-next ",
		NextPseudonym:   " pseudo-next ",
		Keys:            nextKeys,
		Reauthenticated: true,
		Counter:         3,
	})
	if !ok {
		t.Fatal("ApplyUpdate() ok=false, want true")
	}
	if updated.Identity != "reauth-next" || updated.NextPseudonym != "pseudo-next" {
		t.Fatalf("updated identity=%q pseudonym=%q", updated.Identity, updated.NextPseudonym)
	}
	if !updated.Usable() || !updated.CounterOK || updated.Counter != 3 || updated.LastAcceptedCounter != 3 {
		t.Fatalf("updated counters usable=%t state=%+v", updated.Usable(), updated)
	}
	if updated.CounterTooSmall || !updated.Reauthenticated {
		t.Fatalf("updated flags reauthenticated=%t counterTooSmall=%t", updated.Reauthenticated, updated.CounterTooSmall)
	}
	if !bytes.Equal(updated.Keys.MSK, nextKeys.MSK) || !bytes.Equal(updated.Keys.EMSK, nextKeys.EMSK) {
		t.Fatalf("updated keys=%+v", updated.Keys)
	}
	nextKeys.MSK[0] = 0xff
	if updated.Keys.MSK[0] == 0xff {
		t.Fatal("updated state leaked update key slice")
	}
}

func TestEAPReauthenticationStateApplyUpdateCounterTooSmall(t *testing.T) {
	currentKeys := testEAPReauthKeys(0x20)
	state := EAPReauthenticationState{
		Identity:            "reauth-current",
		NextPseudonym:       "pseudo-current",
		Counter:             9,
		CounterOK:           true,
		Keys:                currentKeys,
		LastAcceptedCounter: 9,
		LastRejectedCounter: 4,
	}

	updated, ok := state.ApplyUpdate(EAPReauthenticationUpdate{
		NextReauthID:    " reauth-new ",
		NextPseudonym:   " pseudo-new ",
		Keys:            currentKeys,
		CounterTooSmall: true,
		Counter:         7,
	})
	if !ok {
		t.Fatal("ApplyUpdate() ok=false, want true")
	}
	if updated.Identity != "reauth-new" || updated.NextPseudonym != "pseudo-new" {
		t.Fatalf("updated identity=%q pseudonym=%q", updated.Identity, updated.NextPseudonym)
	}
	if updated.Counter != 9 || !updated.CounterOK || updated.LastAcceptedCounter != 9 || updated.LastRejectedCounter != 7 {
		t.Fatalf("counter-too-small state=%+v", updated)
	}
	if !updated.CounterTooSmall || updated.Reauthenticated {
		t.Fatalf("updated flags reauthenticated=%t counterTooSmall=%t", updated.Reauthenticated, updated.CounterTooSmall)
	}
}

func TestEAPReauthenticationStateApplyUpdateRequiresIdentityAndKeys(t *testing.T) {
	keys := testEAPReauthKeys(0x30)
	state := EAPReauthenticationState{
		Identity:  "reauth-current",
		Counter:   4,
		CounterOK: true,
		Keys:      keys,
	}

	updated, ok := state.ApplyUpdate(EAPReauthenticationUpdate{
		NextReauthID: "reauth-next",
		Keys:         eapaka.Keys{KAut: []byte{1}},
		Counter:      5,
	})
	if ok {
		t.Fatal("ApplyUpdate(incomplete keys) ok=true, want false")
	}
	if updated.Identity != "reauth-current" || updated.Counter != 4 || !updated.CounterOK {
		t.Fatalf("updated state after incomplete keys=%+v", updated)
	}

	updated, ok = (EAPReauthenticationState{}).ApplyUpdate(EAPReauthenticationUpdate{
		NextPseudonym: " pseudo-only ",
		Keys:          keys,
	})
	if ok {
		t.Fatal("ApplyUpdate(missing reauth identity) ok=true, want false")
	}
	if updated.Identity != "" || updated.NextPseudonym != "" {
		t.Fatalf("updated state after missing identity=%+v", updated)
	}
}

func testEAPReauthKeys(seed byte) eapaka.Keys {
	return eapaka.Keys{
		MK:    bytes.Repeat([]byte{seed}, 20),
		KEncr: bytes.Repeat([]byte{seed + 1}, eapaka.KeyLengthKEncr),
		KAut:  bytes.Repeat([]byte{seed + 2}, eapaka.KeyLengthKAut),
		MSK:   bytes.Repeat([]byte{seed + 3}, eapaka.KeyLengthMSK),
		EMSK:  bytes.Repeat([]byte{seed + 4}, eapaka.KeyLengthEMSK),
	}
}
