package sim

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrSyncFailure         = errors.New("aka sync failure")
	ErrAuthFailure         = errors.New("aka authentication failure")
	ErrAKAUnsupported      = errors.New("aka authentication unsupported")
	ErrAKATemporaryFailure = errors.New("aka authentication temporary failure")
)

type AKAApplication string

const (
	AKAApplicationUSIM AKAApplication = "usim"
	AKAApplicationISIM AKAApplication = "isim"
)

type AKAResult struct {
	RES  []byte
	CK   []byte
	IK   []byte
	AUTS []byte
}

type AKAAuthRequest struct {
	Application AKAApplication
	RAND        []byte
	AUTN        []byte
}

func NewAKAAuthRequest(application AKAApplication, rand16, autn16 []byte) (AKAAuthRequest, error) {
	req := AKAAuthRequest{
		Application: NormalizeAKAApplication(application),
		RAND:        append([]byte(nil), rand16...),
		AUTN:        append([]byte(nil), autn16...),
	}
	if err := req.Validate(); err != nil {
		return AKAAuthRequest{}, err
	}
	return req, nil
}

func (r AKAAuthRequest) Clone() AKAAuthRequest {
	return AKAAuthRequest{
		Application: NormalizeAKAApplication(r.Application),
		RAND:        append([]byte(nil), r.RAND...),
		AUTN:        append([]byte(nil), r.AUTN...),
	}
}

func (r AKAAuthRequest) Validate() error {
	switch NormalizeAKAApplication(r.Application) {
	case AKAApplicationUSIM, AKAApplicationISIM:
	default:
		return fmt.Errorf("unsupported AKA application %q", r.Application)
	}
	if len(r.RAND) != 16 {
		return fmt.Errorf("RAND length must be 16 bytes: %d", len(r.RAND))
	}
	if len(r.AUTN) != 16 {
		return fmt.Errorf("AUTN length must be 16 bytes: %d", len(r.AUTN))
	}
	return nil
}

func NormalizeAKAApplication(application AKAApplication) AKAApplication {
	app := strings.ToLower(strings.TrimSpace(string(application)))
	if app == "" {
		return AKAApplicationUSIM
	}
	return AKAApplication(app)
}

type SyncFailureError struct {
	auts []byte
}

func NewSyncFailureError(auts []byte) *SyncFailureError {
	return &SyncFailureError{auts: append([]byte(nil), auts...)}
}

func (e *SyncFailureError) Error() string {
	return ErrSyncFailure.Error()
}

func (e *SyncFailureError) Unwrap() error {
	return ErrSyncFailure
}

func (e *SyncFailureError) AUTS() []byte {
	if e == nil {
		return nil
	}
	return append([]byte(nil), e.auts...)
}

type MACFailureError struct{}

func NewMACFailureError() *MACFailureError {
	return &MACFailureError{}
}

func (e *MACFailureError) Error() string {
	return ErrAuthFailure.Error()
}

func (e *MACFailureError) Unwrap() error {
	return ErrAuthFailure
}

type AKAProvider interface {
	CalculateAKA(rand16, autn16 []byte) (AKAResult, error)
}

type AKAAuthenticator interface {
	AuthenticateAKA(req AKAAuthRequest) (AKAResult, error)
}

type ISIMAKAProvider interface {
	CalculateISIMAKA(rand16, autn16 []byte) (AKAResult, error)
}
