package swu

import (
	"strings"

	"github.com/boa-z/vowifi-go/engine/swu/eapaka"
)

type EAPReauthenticationState struct {
	Identity            string
	Counter             uint16
	CounterOK           bool
	Keys                eapaka.Keys
	NextPseudonym       string
	Reauthenticated     bool
	CounterTooSmall     bool
	LastAcceptedCounter uint16
	LastRejectedCounter uint16
}

type EAPReauthenticationUpdate struct {
	NextReauthID    string
	NextPseudonym   string
	Keys            eapaka.Keys
	Reauthenticated bool
	CounterTooSmall bool
	Counter         uint16
}

func (s EAPReauthenticationState) Usable() bool {
	return strings.TrimSpace(s.Identity) != "" && len(s.Keys.KAut) > 0 && len(s.Keys.KEncr) > 0
}

func (s EAPReauthenticationState) ApplyUpdate(update EAPReauthenticationUpdate) (EAPReauthenticationState, bool) {
	if len(update.Keys.KAut) == 0 || len(update.Keys.KEncr) == 0 {
		return s.clone(), false
	}
	current := s.clone()
	next := current
	if identity := strings.TrimSpace(update.NextReauthID); identity != "" {
		next.Identity = identity
	}
	if pseudonym := strings.TrimSpace(update.NextPseudonym); pseudonym != "" {
		next.NextPseudonym = pseudonym
	}
	if strings.TrimSpace(next.Identity) == "" {
		return current, false
	}
	next.Keys = cloneEAPAKAKeys(update.Keys)
	next.Reauthenticated = update.Reauthenticated
	next.CounterTooSmall = update.CounterTooSmall
	switch {
	case update.Reauthenticated:
		next.Counter = update.Counter
		next.CounterOK = true
		next.LastAcceptedCounter = update.Counter
	case update.CounterTooSmall:
		next.CounterOK = current.CounterOK
		next.LastRejectedCounter = update.Counter
	default:
		next.Counter = 0
		next.CounterOK = true
		next.LastAcceptedCounter = 0
		next.LastRejectedCounter = 0
	}
	return next.clone(), true
}

func (s EAPReauthenticationState) clone() EAPReauthenticationState {
	s.Identity = strings.TrimSpace(s.Identity)
	s.NextPseudonym = strings.TrimSpace(s.NextPseudonym)
	s.Keys = cloneEAPAKAKeys(s.Keys)
	return s
}

func cloneEAPAKAKeys(keys eapaka.Keys) eapaka.Keys {
	return eapaka.Keys{
		MK:      append([]byte(nil), keys.MK...),
		KEncr:   append([]byte(nil), keys.KEncr...),
		KAut:    append([]byte(nil), keys.KAut...),
		KRe:     append([]byte(nil), keys.KRe...),
		MSK:     append([]byte(nil), keys.MSK...),
		EMSK:    append([]byte(nil), keys.EMSK...),
		CKPrime: append([]byte(nil), keys.CKPrime...),
		IKPrime: append([]byte(nil), keys.IKPrime...),
	}
}
