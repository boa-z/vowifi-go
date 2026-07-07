package identity

import (
	"errors"
	"strings"

	"github.com/boa-z/vowifi-go/runtimehost/simtransport"
)

var ErrISIMIdentityDataEmpty = errors.New("ISIM identity data empty")

const (
	IdentityFieldIMSI        = "imsi"
	IdentityFieldIMEI        = "imei"
	IdentityFieldIMSIdentity = "ims_identity"
)

type ISIMIdentityReadError struct {
	Class simtransport.RecoveryClass
	Err   error
}

type FallbackMetadata struct {
	Field                  string
	PrimarySource          string
	FallbackSource         string
	Used                   bool
	RecoveryClass          simtransport.RecoveryClass
	Recoverable            bool
	RecoveryRecommendation simtransport.RecoveryRecommendation
	Reason                 string
}

type classifiedReadError struct {
	Class simtransport.RecoveryClass
	Err   error
}

func (e *ISIMIdentityReadError) Error() string {
	if e == nil || e.Err == nil {
		return ErrISIMIdentityDataEmpty.Error()
	}
	return e.Err.Error()
}

func (e *ISIMIdentityReadError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *ISIMIdentityReadError) RecoveryClass() simtransport.RecoveryClass {
	if e == nil {
		return simtransport.RecoveryClassNone
	}
	return e.Class
}

func (e *classifiedReadError) Error() string {
	if e == nil || e.Err == nil {
		return "ISIM read failed"
	}
	return e.Err.Error()
}

func (e *classifiedReadError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *classifiedReadError) RecoveryClass() simtransport.RecoveryClass {
	if e == nil {
		return simtransport.RecoveryClassNone
	}
	return e.Class
}

func IsISIMIdentityDataEmpty(err error) bool {
	return errors.Is(err, ErrISIMIdentityDataEmpty)
}

func NewReadFallbackMetadata(field, primarySource, fallbackSource string, err error) FallbackMetadata {
	class := simtransport.ClassifyError(err)
	return FallbackMetadata{
		Field:                  normalizeMetadataToken(field),
		PrimarySource:          normalizeMetadataToken(primarySource),
		FallbackSource:         normalizeMetadataToken(fallbackSource),
		Used:                   strings.TrimSpace(fallbackSource) != "",
		RecoveryClass:          class,
		Recoverable:            class.Recoverable(),
		RecoveryRecommendation: simtransport.RecommendRecovery(class, 0),
		Reason:                 errorReason(err),
	}
}

func newISIMIdentityReadError(class simtransport.RecoveryClass, err error) error {
	if err == nil {
		err = ErrISIMIdentityDataEmpty
	}
	if class == simtransport.RecoveryClassNone {
		class = simtransport.ClassifyError(err)
	}
	return &ISIMIdentityReadError{Class: class, Err: err}
}

func newClassifiedReadError(class simtransport.RecoveryClass, err error) error {
	if err == nil {
		return nil
	}
	if class == simtransport.RecoveryClassNone {
		class = simtransport.ClassifyError(err)
	}
	return &classifiedReadError{Class: class, Err: err}
}

func normalizeMetadataToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func errorReason(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}
