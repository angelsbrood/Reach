package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaximumRequestBytes = 16384

type Endpoint struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type Validity struct {
	CA     int64 `json:"ca"`
	Server int64 `json:"server"`
	Client int64 `json:"client"`
}

type Request struct {
	SchemaVersion   int        `json:"schemaVersion"`
	ClusterName     string     `json:"clusterName"`
	ClientName      string     `json:"clientName"`
	ClientID        string     `json:"clientID"`
	Listen          Endpoint   `json:"listen"`
	AdvertisedRoads []Endpoint `json:"advertisedRoads"`
	ModelID         string     `json:"modelID"`
	EXOEndpoint     string     `json:"exoEndpoint"`
	ValiditySeconds *Validity  `json:"validitySeconds,omitempty"`
}

type serviceTLS struct {
	CA    string `json:"clusterCACertificatePath"`
	Chain string `json:"serverCertificateChainPath"`
	Key   string `json:"serverPrivateKeyPath"`
}

type serviceConfig struct {
	SchemaVersion      int        `json:"schemaVersion"`
	ClusterDisplayName string     `json:"clusterDisplayName"`
	Listen             Endpoint   `json:"listen"`
	AdvertisedRoads    []Endpoint `json:"advertisedRoads"`
	TLS                serviceTLS `json:"tls"`
	ModelID            string     `json:"modelID"`
	EXOEndpoint        string     `json:"exoEndpoint"`
}

func (r Request) service() serviceConfig {
	return serviceConfig{1, r.ClusterName, r.Listen, r.AdvertisedRoads, serviceTLS{"/etc/reach/tls/ca.pem", "/etc/reach/tls/server-chain.pem", "/etc/reach/tls/server-key.pem"}, r.ModelID, r.EXOEndpoint}
}

func (r Request) validity() Validity {
	if r.ValiditySeconds != nil {
		return *r.ValiditySeconds
	}
	return Validity{2 * 365 * 86400, 30 * 86400, 365 * 86400}
}

func LoadRequest(path string) (Request, error) {
	data, err := readPrivate(path, MaximumRequestBytes)
	if err != nil {
		return Request{}, err
	}
	return DecodeRequest(data)
}

func DecodeRequest(data []byte) (Request, error) {
	var r Request
	if err := strictJSON(data, MaximumRequestBytes, &r); err != nil {
		return r, err
	}
	if err := r.validate(); err != nil {
		return Request{}, err
	}
	r.ClientID = strings.ToLower(r.ClientID)
	return r, nil
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (r Request) validate() error {
	if r.SchemaVersion != 1 || !printable(r.ClusterName, 128) || !printable(r.ClientName, 128) || !printable(r.ModelID, 256) {
		return errors.New("invalid request schema or bounded ASCII name/model")
	}
	if !uuidPattern.MatchString(r.ClientID) {
		return errors.New("clientID must be a hyphenated UUID")
	}
	if !validEndpoint(r.Listen, true) || len(r.AdvertisedRoads) < 1 || len(r.AdvertisedRoads) > 16 {
		return errors.New("invalid listener or advertised roads")
	}
	seen := map[Endpoint]bool{}
	for _, e := range r.AdvertisedRoads {
		if !validEndpoint(e, false) || seen[e] {
			return errors.New("invalid or duplicate advertised road")
		}
		seen[e] = true
	}
	u, err := url.Parse(r.EXOEndpoint)
	if err != nil {
		return errors.New("invalid EXO endpoint")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	port, perr := strconv.Atoi(u.Port())
	if err != nil || perr != nil || ip.String() != "127.0.0.1" || port < 1024 || port > 65535 || r.EXOEndpoint != "http://127.0.0.1:"+strconv.Itoa(port) {
		return errors.New("EXO endpoint must be http://127.0.0.1:<port> with an explicit canonical unprivileged port")
	}
	v := r.validity()
	if v.CA < 1 || v.CA > 2*365*86400 || v.Server < 1 || v.Server > 30*86400 || v.Client < 1 || v.Client > 365*86400 || v.Server > v.CA || v.Client > v.CA {
		return errors.New("invalid validitySeconds; leaves must fit within CA validity")
	}
	return nil
}

func printable(s string, maximum int) bool {
	if len(s) < 1 || len(s) > maximum || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range []byte(s) {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func validEndpoint(e Endpoint, wildcard bool) bool {
	a, err := netip.ParseAddr(e.Address)
	return err == nil && a.Is4() && a.String() == e.Address && !a.IsMulticast() && a.String() != "255.255.255.255" && (wildcard || !a.IsUnspecified()) && e.Port >= 1024 && e.Port <= 65535
}

// Token inspection rejects duplicate names before ordinary typed decoding.
// Shape checking makes JSON field names case-sensitive and rejects missing/null fields.
func strictJSON(data []byte, limit int, target any) error {
	if len(data) == 0 || len(data) > limit || !utf8.Valid(data) {
		return errors.New("JSON document exceeds its size bound or is empty")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := scanJSON(d, 0); err != nil {
		return errors.New("malformed, duplicate or overly nested JSON")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value any
	if err := d.Decode(&value); err != nil {
		return errors.New("malformed JSON")
	}
	if !shape(value, reflect.TypeOf(target).Elem()) {
		return errors.New("unknown, missing, null or incorrectly shaped JSON field")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return errors.New("invalid JSON field value")
	}
	return nil
}

func scanJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("depth")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := k.(string)
			if !ok || seen[name] {
				return errors.New("duplicate")
			}
			seen[name] = true
			if err := scanJSON(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("object")
		}
	case json.Delim('['):
		for d.More() {
			if err := scanJSON(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("array")
		}
	case json.Delim('}'), json.Delim(']'):
		return errors.New("unexpected delimiter")
	}
	return nil
}

func shape(value any, t reflect.Type) bool {
	if value == nil {
		return false
	}
	if t.Kind() == reflect.Pointer {
		return shape(value, t.Elem())
	}
	switch t.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		allowed := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")
			name := tag[0]
			allowed[name] = true
			v, present := object[name]
			if !present {
				if len(tag) > 1 && tag[1] == "omitempty" {
					continue
				}
				return false
			}
			if !shape(v, field.Type) {
				return false
			}
		}
		for name := range object {
			if !allowed[name] {
				return false
			}
		}
		return true
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			_, ok := value.(string)
			return ok
		}
		array, ok := value.([]any)
		if !ok {
			return false
		}
		for _, v := range array {
			if !shape(v, t.Elem()) {
				return false
			}
		}
		return true
	case reflect.String:
		_, ok := value.(string)
		return ok
	case reflect.Int, reflect.Int64:
		_, ok := value.(json.Number)
		return ok
	}
	return false
}
