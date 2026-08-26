package target

import "github.com/cumakurt/garga/internal/model"

const defaultElasticsearchPort = 9200

// Endpoint converts a canonical target into a concrete HTTP endpoint.
// Scheme-less targets use HTTP. A missing port uses 9200, or the URL scheme default
// when the target already selected HTTP or HTTPS.
func Endpoint(target model.Target) (model.Endpoint, error) {
	scheme := target.SchemeHint
	port := target.Port
	if scheme == model.SchemeAuto {
		scheme = model.SchemeHTTP
		if port == 0 {
			port = defaultElasticsearchPort
		}
	} else if port == 0 {
		if scheme == model.SchemeHTTPS {
			port = 443
		} else {
			port = 80
		}
	}
	endpoint := model.Endpoint{
		Scheme: scheme,
		Host:   target.Host,
		Port:   port,
		Path:   target.Path,
	}
	if _, err := endpoint.URL(); err != nil {
		return model.Endpoint{}, err
	}
	return endpoint, nil
}
