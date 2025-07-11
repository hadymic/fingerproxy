package reverseproxy

import "net/http"

type HeaderInjector interface {
	GetHeaderName() string

	GetFieldName() string

	GetHeaderValue(req *http.Request) (string, error)
}
