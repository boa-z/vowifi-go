package messaging

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strconv"
	"strings"
)

const IMSUSSDContentType = "application/vnd.3gpp.ussd+xml"
const IMSUSSDInfoPackage = "g.3gpp.ussd"
const IMSUSSDContentDisposition = "Info-Package"

type IMSUSSDOperation string

const (
	IMSUSSDOperationRequest IMSUSSDOperation = "request"
	IMSUSSDOperationNotify  IMSUSSDOperation = "notify"
)

type IMSUSSDPayload struct {
	Language            string
	Text                string
	Operation           IMSUSSDOperation
	ErrorCode           int
	HasError            bool
	AlertingPattern     int
	HasAlertingPattern  bool
	RawOperationElement string
}

type ussdDataXML struct {
	XMLName               xml.Name       `xml:"ussd-data"`
	Language              string         `xml:"language,omitempty"`
	String                string         `xml:"ussd-string,omitempty"`
	ErrorCode             string         `xml:"error-code,omitempty"`
	UnstructuredSSRequest *struct{}      `xml:"UnstructuredSS-Request,omitempty"`
	UnstructuredSSNotify  *struct{}      `xml:"UnstructuredSS-Notify,omitempty"`
	AlertingPattern       string         `xml:"alertingPattern,omitempty"`
	AnyExt                *ussdAnyExtXML `xml:"anyExt,omitempty"`
}

type ussdAnyExtXML struct {
	UnstructuredSSRequest *struct{} `xml:"UnstructuredSS-Request,omitempty"`
	UnstructuredSSNotify  *struct{} `xml:"UnstructuredSS-Notify,omitempty"`
	AlertingPattern       string    `xml:"alertingPattern,omitempty"`
}

func BuildIMSUSSDXML(payload IMSUSSDPayload) ([]byte, error) {
	text := strings.TrimSpace(payload.Text)
	if text == "" && !payload.HasError {
		return nil, errors.New("USSD text is empty")
	}
	language := strings.TrimSpace(payload.Language)
	if language == "" {
		language = "en"
	}
	if strings.ContainsAny(language, " \t\r\n") {
		return nil, fmt.Errorf("USSD language contains whitespace: %q", language)
	}
	op := payload.Operation
	if op == "" {
		op = IMSUSSDOperationRequest
	}
	data := ussdDataXML{
		Language: language,
		String:   text,
	}
	if payload.HasError {
		if payload.ErrorCode < 0 || payload.ErrorCode > 65535 {
			return nil, fmt.Errorf("USSD error code out of range: %d", payload.ErrorCode)
		}
		data.ErrorCode = strconv.Itoa(payload.ErrorCode)
	}
	switch op {
	case IMSUSSDOperationRequest:
		data.UnstructuredSSRequest = &struct{}{}
	case IMSUSSDOperationNotify:
		data.UnstructuredSSNotify = &struct{}{}
	default:
		return nil, fmt.Errorf("unsupported USSD operation: %s", op)
	}
	if payload.HasAlertingPattern {
		if payload.AlertingPattern < 0 || payload.AlertingPattern > 255 {
			return nil, fmt.Errorf("USSD alerting pattern out of range: %d", payload.AlertingPattern)
		}
		data.AlertingPattern = strconv.Itoa(payload.AlertingPattern)
	}
	out, err := xml.Marshal(data)
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

func ParseIMSUSSDXML(body []byte) (IMSUSSDPayload, error) {
	body = []byte(strings.TrimSpace(string(body)))
	if len(body) == 0 {
		return IMSUSSDPayload{}, errors.New("USSD XML body is empty")
	}
	var data ussdDataXML
	if err := xml.Unmarshal(body, &data); err != nil {
		return IMSUSSDPayload{}, err
	}
	if data.XMLName.Local != "ussd-data" {
		return IMSUSSDPayload{}, fmt.Errorf("unexpected USSD XML root: %s", data.XMLName.Local)
	}
	payload := IMSUSSDPayload{
		Language: strings.TrimSpace(data.Language),
		Text:     strings.ToValidUTF8(data.String, ""),
	}
	if data.UnstructuredSSRequest != nil {
		payload.Operation = IMSUSSDOperationRequest
		payload.RawOperationElement = "UnstructuredSS-Request"
	}
	if data.UnstructuredSSNotify != nil {
		payload.Operation = IMSUSSDOperationNotify
		payload.RawOperationElement = "UnstructuredSS-Notify"
	}
	if data.AnyExt != nil {
		if payload.Operation == "" && data.AnyExt.UnstructuredSSRequest != nil {
			payload.Operation = IMSUSSDOperationRequest
			payload.RawOperationElement = "UnstructuredSS-Request"
		}
		if payload.Operation == "" && data.AnyExt.UnstructuredSSNotify != nil {
			payload.Operation = IMSUSSDOperationNotify
			payload.RawOperationElement = "UnstructuredSS-Notify"
		}
		if strings.TrimSpace(data.AlertingPattern) == "" {
			data.AlertingPattern = data.AnyExt.AlertingPattern
		}
	}
	if strings.TrimSpace(data.ErrorCode) != "" {
		code, err := strconv.Atoi(strings.TrimSpace(data.ErrorCode))
		if err != nil {
			return IMSUSSDPayload{}, fmt.Errorf("invalid USSD error code: %w", err)
		}
		payload.ErrorCode = code
		payload.HasError = true
	}
	if strings.TrimSpace(data.AlertingPattern) != "" {
		pattern, err := strconv.Atoi(strings.TrimSpace(data.AlertingPattern))
		if err != nil {
			return IMSUSSDPayload{}, fmt.Errorf("invalid USSD alerting pattern: %w", err)
		}
		payload.AlertingPattern = pattern
		payload.HasAlertingPattern = true
	}
	if payload.Operation == "" {
		payload.Operation = IMSUSSDOperationNotify
	}
	return payload, nil
}

func normalizeUSSDContentType(contentType string) string {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	if semi := strings.IndexByte(contentType, ';'); semi >= 0 {
		contentType = strings.TrimSpace(contentType[:semi])
	}
	return contentType
}

func DecodeIMSUSSDDocument(contentType string, body []byte) (IMSUSSDPayload, bool, error) {
	contentType = strings.TrimSpace(contentType)
	if len(bytes.TrimSpace(body)) == 0 {
		return IMSUSSDPayload{}, false, nil
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = normalizeUSSDContentType(contentType)
	}
	switch strings.ToLower(mediaType) {
	case IMSUSSDContentType:
		payload, err := ParseIMSUSSDXML(body)
		return payload, true, err
	case "multipart/mixed", "multipart/related":
		boundary := strings.TrimSpace(params["boundary"])
		if boundary == "" {
			return IMSUSSDPayload{}, false, errors.New("USSD multipart boundary is empty")
		}
		reader := multipart.NewReader(bytes.NewReader(body), boundary)
		for {
			part, err := reader.NextPart()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return IMSUSSDPayload{}, false, err
			}
			partBody, err := io.ReadAll(part)
			if err != nil {
				return IMSUSSDPayload{}, false, err
			}
			if normalizeUSSDContentType(part.Header.Get("Content-Type")) != IMSUSSDContentType {
				continue
			}
			payload, err := ParseIMSUSSDXML(partBody)
			return payload, true, err
		}
		return IMSUSSDPayload{}, false, nil
	default:
		if bytes.HasPrefix(bytes.TrimSpace(body), []byte("<")) {
			payload, err := ParseIMSUSSDXML(body)
			return payload, true, err
		}
		return IMSUSSDPayload{}, false, nil
	}
}

func ussdResultFromPayload(sessionID string, payload IMSUSSDPayload, status int) USSDResult {
	done := payload.HasError || payload.Operation == IMSUSSDOperationNotify
	res := USSDResult{
		SessionID: sessionID,
		Text:      payload.Text,
		RawText:   payload.Text,
		Status:    status,
		DCS:       15,
		Done:      done,
	}
	if payload.HasError {
		res.Status = payload.ErrorCode
	}
	return normalizeUSSDResult(res, sessionID)
}
