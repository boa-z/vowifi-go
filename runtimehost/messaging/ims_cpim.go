package messaging

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"time"
)

const IMSCPIMContentType = "message/cpim"

const imsContentTransferEncodingHeader = "Content-Transfer-Encoding"
const imsCPIMIMDNNamespace = "urn:ietf:params:imdn"
const imsIMDNContentType = "message/imdn+xml"

type IMSCPIMMessage struct {
	Headers        map[string][]string
	ContentHeaders map[string][]string
	ContentType    string
	Body           []byte
}

func ParseIMSCPIMMessage(body []byte) (IMSCPIMMessage, error) {
	messageHeaderBlock, rest, ok := splitCPIMHeaderBlock(body)
	if !ok {
		return IMSCPIMMessage{}, errors.New("CPIM message headers missing terminator")
	}
	messageHeaders, err := parseCPIMHeaders(messageHeaderBlock)
	if err != nil {
		return IMSCPIMMessage{}, fmt.Errorf("CPIM message headers: %w", err)
	}
	contentHeaderBlock, content, ok := splitCPIMHeaderBlock(rest)
	if !ok {
		return IMSCPIMMessage{}, errors.New("CPIM content headers missing terminator")
	}
	contentHeaders, err := parseCPIMHeaders(contentHeaderBlock)
	if err != nil {
		return IMSCPIMMessage{}, fmt.Errorf("CPIM content headers: %w", err)
	}
	contentType := normalizedIMSMessageContentType(textproto.MIMEHeader(contentHeaders).Get("Content-Type"))
	if contentType == "" {
		return IMSCPIMMessage{}, errors.New("CPIM content type is empty")
	}
	if contentLength := strings.TrimSpace(textproto.MIMEHeader(contentHeaders).Get("Content-Length")); contentLength != "" {
		n, err := strconv.Atoi(contentLength)
		if err != nil || n < 0 {
			return IMSCPIMMessage{}, fmt.Errorf("invalid CPIM content length: %q", contentLength)
		}
		if n > len(content) {
			return IMSCPIMMessage{}, errors.New("CPIM content truncated")
		}
		content = content[:n]
	}
	content, _, err = decodeIMSContentTransferEncoding(contentHeaders, content)
	if err != nil {
		return IMSCPIMMessage{}, fmt.Errorf("CPIM content: %w", err)
	}
	return IMSCPIMMessage{
		Headers:        messageHeaders,
		ContentHeaders: contentHeaders,
		ContentType:    contentType,
		Body:           append([]byte(nil), content...),
	}, nil
}

type imsCPIMIMDNReport struct {
	MessageID            string
	DateTime             time.Time
	RecipientURI         string
	OriginalRecipientURI string
	Notification         string
	Status               string
	StatusText           string
	State                string
	ErrorText            string
}

type imsIMDNXMLDocument struct {
	XMLName              xml.Name             `xml:"imdn"`
	MessageID            string               `xml:"message-id"`
	DateTime             string               `xml:"datetime"`
	RecipientURI         string               `xml:"recipient-uri"`
	OriginalRecipientURI string               `xml:"original-recipient-uri"`
	Delivery             *imsIMDNNotification `xml:"delivery-notification"`
	Display              *imsIMDNNotification `xml:"display-notification"`
	Processing           *imsIMDNNotification `xml:"processing-notification"`
}

type imsIMDNNotification struct {
	Status imsIMDNStatus `xml:"status"`
}

type imsIMDNStatus struct {
	Delivered *struct{} `xml:"delivered"`
	Displayed *struct{} `xml:"displayed"`
	Processed *struct{} `xml:"processed"`
	Stored    *struct{} `xml:"stored"`
	Failed    *struct{} `xml:"failed"`
	Forbidden *struct{} `xml:"forbidden"`
	Error     *struct{} `xml:"error"`
	Text      string
}

func parseIMSCPIMIMDNReport(cpim IMSCPIMMessage) (imsCPIMIMDNReport, error) {
	if normalizedIMSMessageContentType(cpim.ContentType) != imsIMDNContentType {
		return imsCPIMIMDNReport{}, fmt.Errorf("not IMDN content type: %s", cpim.ContentType)
	}
	headers := cloneCPIMHeaders(cpim.Headers)
	normalizeCPIMIMDNHeaders(headers)

	var doc imsIMDNXMLDocument
	decoder := xml.NewDecoder(bytes.NewReader(cpim.Body))
	if err := decoder.Decode(&doc); err != nil {
		return imsCPIMIMDNReport{}, fmt.Errorf("IMDN XML: %w", err)
	}
	if !strings.EqualFold(doc.XMLName.Local, "imdn") {
		return imsCPIMIMDNReport{}, fmt.Errorf("IMDN root is %q, want imdn", doc.XMLName.Local)
	}

	notification, status := imsIMDNNotificationStatus(doc)
	if status == "" {
		return imsCPIMIMDNReport{}, errors.New("IMDN status is empty")
	}
	state, ok := imsIMDNDeliveryState(status)
	if !ok {
		return imsCPIMIMDNReport{}, fmt.Errorf("unsupported IMDN status: %s", status)
	}
	reportAt, err := parseIMSCPIMIMDNTime(firstNonEmpty(doc.DateTime, firstCPIMHeaderValue(headers, "DateTime"), firstCPIMHeaderValue(headers, "imdn.DateTime")))
	if err != nil {
		return imsCPIMIMDNReport{}, err
	}

	return imsCPIMIMDNReport{
		MessageID:            firstNonEmpty(doc.MessageID, firstCPIMHeaderValue(headers, "imdn.Message-ID")),
		DateTime:             reportAt,
		RecipientURI:         firstNonEmpty(doc.RecipientURI, firstCPIMHeaderValue(headers, "To")),
		OriginalRecipientURI: firstNonEmpty(doc.OriginalRecipientURI, firstCPIMHeaderValue(headers, "imdn.Original-To")),
		Notification:         notification,
		Status:               status,
		StatusText:           doc.notificationStatusText(notification),
		State:                state,
		ErrorText:            imsIMDNErrorText(notification, status, state, doc.notificationStatusText(notification)),
	}, nil
}

func imsIMDNNotificationStatus(doc imsIMDNXMLDocument) (string, string) {
	if doc.Delivery != nil {
		return "delivery", doc.Delivery.Status.value()
	}
	if doc.Display != nil {
		return "display", doc.Display.Status.value()
	}
	if doc.Processing != nil {
		return "processing", doc.Processing.Status.value()
	}
	return "", ""
}

func (s imsIMDNStatus) value() string {
	switch {
	case s.Delivered != nil:
		return "delivered"
	case s.Displayed != nil:
		return "displayed"
	case s.Processed != nil:
		return "processed"
	case s.Stored != nil:
		return "stored"
	case s.Failed != nil:
		return "failed"
	case s.Forbidden != nil:
		return "forbidden"
	case s.Error != nil:
		return "error"
	default:
		return normalizeIMSIMDNStatusText(s.Text)
	}
}

func (doc imsIMDNXMLDocument) notificationStatusText(notification string) string {
	switch notification {
	case "delivery":
		if doc.Delivery != nil {
			return strings.TrimSpace(doc.Delivery.Status.Text)
		}
	case "display":
		if doc.Display != nil {
			return strings.TrimSpace(doc.Display.Status.Text)
		}
	case "processing":
		if doc.Processing != nil {
			return strings.TrimSpace(doc.Processing.Status.Text)
		}
	}
	return ""
}

func (s *imsIMDNStatus) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	var text strings.Builder
	for {
		tok, err := decoder.Token()
		if err != nil {
			return err
		}
		switch item := tok.(type) {
		case xml.StartElement:
			childText, err := readIMSXMLText(decoder, item)
			if err != nil {
				return err
			}
			if s.setStatusElement(item.Name.Local) && strings.TrimSpace(childText) != "" {
				appendIMSStatusText(&text, childText)
				continue
			}
			appendIMSStatusText(&text, childText)
		case xml.CharData:
			appendIMSStatusText(&text, string(item))
		case xml.EndElement:
			if item.Name == start.Name {
				s.Text = strings.TrimSpace(text.String())
				return nil
			}
		}
	}
}

func (s *imsIMDNStatus) setStatusElement(name string) bool {
	switch normalizeIMSIMDNStatusText(name) {
	case "delivered":
		s.Delivered = &struct{}{}
	case "displayed":
		s.Displayed = &struct{}{}
	case "processed":
		s.Processed = &struct{}{}
	case "stored":
		s.Stored = &struct{}{}
	case "failed":
		s.Failed = &struct{}{}
	case "forbidden":
		s.Forbidden = &struct{}{}
	case "error":
		s.Error = &struct{}{}
	default:
		return false
	}
	return true
}

func normalizeIMSIMDNStatusText(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "delivered", "displayed", "processed", "stored", "failed", "forbidden", "error":
		return value
	default:
		return ""
	}
}

func imsIMDNDeliveryState(status string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "delivered", "displayed", "processed":
		return "delivered", true
	case "stored":
		return "accepted", true
	case "failed", "forbidden", "error":
		return "failed", true
	default:
		return "", false
	}
}

func parseIMSCPIMIMDNTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999999Z0700",
		"2006-01-02T15:04:05Z0700",
		time.RFC1123Z,
		time.RFC1123,
	} {
		if reportAt, err := time.Parse(layout, value); err == nil {
			return reportAt, nil
		}
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	} {
		if reportAt, err := time.ParseInLocation(layout, value, time.UTC); err == nil {
			return reportAt, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid IMDN datetime: %q", value)
}

func imsIMDNErrorText(notification, status, state, detail string) string {
	if state != "failed" {
		return ""
	}
	notification = firstNonEmpty(notification, "delivery")
	status = firstNonEmpty(status, "failed")
	detail = strings.TrimSpace(detail)
	if detail != "" && !strings.EqualFold(detail, status) {
		return "IMDN " + notification + " notification " + status + ": " + detail
	}
	return "IMDN " + notification + " notification " + status
}

func readIMSXMLText(decoder *xml.Decoder, start xml.StartElement) (string, error) {
	var text strings.Builder
	for {
		tok, err := decoder.Token()
		if err != nil {
			return "", err
		}
		switch item := tok.(type) {
		case xml.StartElement:
			childText, err := readIMSXMLText(decoder, item)
			if err != nil {
				return "", err
			}
			appendIMSStatusText(&text, childText)
		case xml.CharData:
			appendIMSStatusText(&text, string(item))
		case xml.EndElement:
			if item.Name == start.Name {
				return strings.TrimSpace(text.String()), nil
			}
		}
	}
}

func appendIMSStatusText(out *strings.Builder, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if out.Len() > 0 {
		out.WriteByte(' ')
	}
	out.WriteString(value)
}

func BuildIMSCPIMMessage(from, to, contentType string, body []byte) ([]byte, error) {
	messageHeaders := make(map[string][]string, 2)
	if strings.TrimSpace(from) != "" {
		messageHeaders["From"] = []string{strings.TrimSpace(from)}
	}
	if strings.TrimSpace(to) != "" {
		messageHeaders["To"] = []string{strings.TrimSpace(to)}
	}
	return BuildIMSCPIMMessageWithHeaders(messageHeaders, map[string][]string{"Content-Type": {contentType}}, body)
}

func BuildIMSCPIMMessageWithHeaders(messageHeaders, contentHeaders map[string][]string, body []byte) ([]byte, error) {
	contentType := firstCPIMHeaderValue(contentHeaders, "Content-Type")
	if strings.TrimSpace(contentType) == "" {
		return nil, errors.New("CPIM content type is empty")
	}
	contentHeaders = cloneCPIMHeaders(contentHeaders)
	setCPIMHeader(contentHeaders, "Content-Length", strconv.Itoa(len(body)))
	var out bytes.Buffer
	if err := writeCPIMHeaders(&out, messageHeaders); err != nil {
		return nil, err
	}
	out.WriteString("\r\n")
	if err := writeCPIMHeaders(&out, contentHeaders); err != nil {
		return nil, err
	}
	out.WriteString("\r\n")
	out.Write(body)
	return out.Bytes(), nil
}

func splitCPIMHeaderBlock(data []byte) (block []byte, rest []byte, ok bool) {
	crlf := bytes.Index(data, []byte("\r\n\r\n"))
	lf := bytes.Index(data, []byte("\n\n"))
	switch {
	case crlf >= 0 && (lf < 0 || crlf <= lf):
		return data[:crlf], data[crlf+4:], true
	case lf >= 0:
		return data[:lf], data[lf+2:], true
	default:
		return nil, nil, false
	}
}

func parseCPIMHeaders(block []byte) (map[string][]string, error) {
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(append([]byte(nil), block...), []byte("\r\n\r\n")...))))
	header, err := reader.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(header))
	for key, values := range header {
		out[key] = append([]string(nil), values...)
	}
	normalizeCPIMIMDNHeaders(out)
	return out, nil
}

func normalizedIMSMessageContentType(contentType string) string {
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err == nil {
		return strings.ToLower(strings.TrimSpace(mediaType))
	}
	if semi := strings.IndexByte(contentType, ';'); semi >= 0 {
		contentType = contentType[:semi]
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

func decodeIMSContentTransferEncoding(headers map[string][]string, body []byte) ([]byte, bool, error) {
	encoding := normalizeIMSContentTransferEncoding(firstCPIMHeaderValue(headers, imsContentTransferEncodingHeader))
	if encoding == "" {
		return body, false, nil
	}
	switch encoding {
	case "7bit", "8bit", "binary":
		return body, true, nil
	case "base64":
		decoded, err := decodeIMSBase64Content(body)
		if err != nil {
			return nil, true, fmt.Errorf("invalid IMS content-transfer-encoding base64: %w", err)
		}
		return decoded, true, nil
	case "quoted-printable":
		decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
		if err != nil {
			return nil, true, fmt.Errorf("invalid IMS content-transfer-encoding quoted-printable: %w", err)
		}
		return decoded, true, nil
	default:
		return nil, true, fmt.Errorf("unsupported IMS content-transfer-encoding: %s", encoding)
	}
}

func normalizeIMSContentTransferEncoding(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	if value == "" {
		return ""
	}
	if token, _, ok := strings.Cut(value, ";"); ok {
		value = token
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func decodeIMSBase64Content(body []byte) ([]byte, error) {
	compact := make([]byte, 0, len(body))
	for _, b := range body {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			compact = append(compact, b)
		}
	}
	if len(compact) == 0 {
		return []byte{}, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(string(compact))
	if err == nil {
		return decoded, nil
	}
	if decoded, rawErr := base64.RawStdEncoding.DecodeString(string(compact)); rawErr == nil {
		return decoded, nil
	}
	return nil, err
}

func cloneCPIMHeaders(headers map[string][]string) map[string][]string {
	out := make(map[string][]string, len(headers))
	for key, values := range headers {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func firstCPIMHeaderValue(headers map[string][]string, key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	for candidate, values := range headers {
		if strings.ToLower(strings.TrimSpace(candidate)) == key {
			for _, value := range values {
				if strings.TrimSpace(value) != "" {
					return value
				}
			}
		}
	}
	return ""
}

func setCPIMHeader(headers map[string][]string, key, value string) {
	for candidate := range headers {
		if strings.EqualFold(strings.TrimSpace(candidate), key) {
			delete(headers, candidate)
		}
	}
	headers[key] = []string{value}
}

func normalizeCPIMIMDNHeaders(headers map[string][]string) {
	prefixes := cpimNamespacePrefixes(headers, imsCPIMIMDNNamespace)
	if len(prefixes) == 0 {
		return
	}
	normalized := make(map[string][]string, len(headers))
	changed := false
	for key, values := range headers {
		target := key
		if normalizedKey, ok := normalizeCPIMIMDNHeaderName(key, prefixes); ok {
			target = normalizedKey
			if key != normalizedKey {
				changed = true
			}
		}
		appendCPIMHeaderValues(normalized, target, values)
	}
	if !changed {
		return
	}
	for key := range headers {
		delete(headers, key)
	}
	for key, values := range normalized {
		headers[key] = values
	}
}

func cpimNamespacePrefixes(headers map[string][]string, namespaceURI string) map[string]bool {
	prefixes := map[string]bool{}
	for _, value := range cpimHeaderValues(headers, "NS") {
		prefix, uri, ok := parseCPIMNamespaceHeader(value)
		if !ok || !strings.EqualFold(uri, namespaceURI) {
			continue
		}
		prefixes[strings.ToLower(prefix)] = true
	}
	return prefixes
}

func cpimHeaderValues(headers map[string][]string, key string) []string {
	var out []string
	for candidate, values := range headers {
		if strings.EqualFold(strings.TrimSpace(candidate), key) {
			out = append(out, values...)
		}
	}
	return out
}

func parseCPIMNamespaceHeader(value string) (prefix, uri string, ok bool) {
	value = strings.TrimSpace(value)
	start := strings.IndexByte(value, '<')
	end := strings.LastIndexByte(value, '>')
	if start <= 0 || end <= start {
		return "", "", false
	}
	prefix = strings.TrimSpace(value[:start])
	uri = strings.TrimSpace(value[start+1 : end])
	if !validCPIMHeaderName(prefix) || uri == "" {
		return "", "", false
	}
	return prefix, uri, true
}

func normalizeCPIMIMDNHeaderName(name string, prefixes map[string]bool) (string, bool) {
	name = strings.TrimSpace(name)
	prefix, suffix, ok := strings.Cut(name, ".")
	if !ok || strings.TrimSpace(suffix) == "" {
		return "", false
	}
	lowerPrefix := strings.ToLower(prefix)
	if lowerPrefix != "imdn" && !prefixes[lowerPrefix] {
		return "", false
	}
	return "imdn." + canonicalCPIMIMDNHeaderSuffix(suffix), true
}

func canonicalCPIMIMDNHeaderSuffix(suffix string) string {
	switch strings.ToLower(strings.TrimSpace(suffix)) {
	case "message-id":
		return "Message-ID"
	case "disposition-notification":
		return "Disposition-Notification"
	case "original-to":
		return "Original-To"
	case "datetime":
		return "DateTime"
	default:
		return strings.TrimSpace(suffix)
	}
}

func appendCPIMHeaderValues(headers map[string][]string, key string, values []string) {
	for candidate, existing := range headers {
		if !strings.EqualFold(strings.TrimSpace(candidate), key) {
			continue
		}
		if candidate != key {
			delete(headers, candidate)
		}
		headers[key] = append(append([]string(nil), existing...), values...)
		return
	}
	headers[key] = append([]string(nil), values...)
}

func writeCPIMHeaders(out *bytes.Buffer, headers map[string][]string) error {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return strings.ToLower(strings.TrimSpace(keys[i])) < strings.ToLower(strings.TrimSpace(keys[j]))
	})
	for _, key := range keys {
		name := strings.TrimSpace(key)
		if !validCPIMHeaderName(name) {
			return fmt.Errorf("invalid CPIM header name: %q", key)
		}
		for _, value := range headers[key] {
			if strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("invalid CPIM header %s value contains line break", name)
			}
			if strings.TrimSpace(value) == "" {
				continue
			}
			fmt.Fprintf(out, "%s: %s\r\n", name, strings.TrimSpace(value))
		}
	}
	return nil
}

func validCPIMHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			continue
		case r == '!', r == '#', r == '$', r == '%', r == '&', r == '\'', r == '*', r == '+',
			r == '-', r == '.', r == '^', r == '_', r == '`', r == '|', r == '~':
			continue
		default:
			return false
		}
	}
	return true
}
