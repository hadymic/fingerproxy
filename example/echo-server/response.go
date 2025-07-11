package main

import (
	"log"

	"github.com/dreadl0ck/tlsx"
	"github.com/wi1dcard/fingerproxy/pkg/ja3"
	"github.com/wi1dcard/fingerproxy/pkg/ja4"
	"github.com/wi1dcard/fingerproxy/pkg/metadata"
)

// echoResponse is the HTTP response struct of this echo server
type echoResponse struct {
	Detail    *detailResponse `json:"detail,omitempty"`
	JA3       string          `json:"ja3"`
	JA3Raw    string          `json:"ja3_text"`
	JA4       string          `json:"ja4"`
	JA4Raw    string          `json:"ja4_ro"`
	HTTP2     string          `json:"akamai_text"`
	UserAgent string          `json:"user_agent"`

	log *log.Logger
}

type detailResponse struct {
	Metadata  *metadata.Metadata `json:"metadata"`
	UserAgent string             `json:"user_agent"`
	JA3       *ja3Detail         `json:"ja3"`
	JA3Raw    string             `json:"ja3_raw"`
	JA4       *ja4Detail         `json:"ja4"`
	JA4Raw    string             `json:"ja4_raw"`
}

func (r *echoResponse) fingerprintJA3() error {
	fp := &tlsx.ClientHelloBasic{}
	rd := r.Detail
	err := fp.Unmarshal(rd.Metadata.ClientHelloRecord)
	if err != nil {
		return err
	}

	ja3Raw := ja3.Bare(fp)

	rd.JA3 = (*ja3Detail)(fp)
	rd.JA3Raw = string(ja3Raw)
	r.JA3 = ja3.BareToDigestHex(ja3Raw)
	r.JA3Raw = string(ja3Raw)

	r.logf("ja3: %s", r.JA3)
	return nil
}

func (r *echoResponse) fingerprintJA4() error {
	fp := &ja4.JA4Fingerprint{}
	rd := r.Detail
	err := fp.UnmarshalBytes(rd.Metadata.ClientHelloRecord, 't')
	if err != nil {
		return err
	}

	rd.JA4 = (*ja4Detail)(fp)
	r.JA4 = fp.String()

	r.logf("ja4: %s", r.JA4)
	return nil
}

func (r *echoResponse) fingerprintJA4RO() error {
	fp := &ja4.JA4Fingerprint{}
	rd := r.Detail
	err := fp.UnmarshalOriginalBytes(rd.Metadata.ClientHelloRecord, 't')
	if err != nil {
		return err
	}

	rd.JA4Raw = fp.ROString()
	r.JA4Raw = fp.ROString()

	r.logf("ja4_ro: %s", r.JA4)
	return nil
}

func (r *echoResponse) fingerrpintHTTP2() {
	protocol := r.Detail.Metadata.ConnectionState.NegotiatedProtocol
	if protocol == "h2" {
		r.HTTP2 = r.Detail.Metadata.HTTP2Frames.String()
		r.logf("http2: %s", r.HTTP2)
	} else if *flagVerbose {
		r.logf("protocol is %s, skipping HTTP2 fingerprinting", protocol)
	}
}

func (r *echoResponse) logf(format string, args ...any) {
	if !*flagQuiet {
		r.log.Printf(format, args...)
	}
}
