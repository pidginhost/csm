package checks

import (
	"net/netip"
	"strings"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// AdmissionEvidence is what a finding asks admission to mint: the producer
// that stamped its observation and the evidence input that producer attests,
// aimed at the address the finding's parser read. A finding
// without an observation, naming a producer the table does not list, or
// whose parser vouched for no address asks for nothing: provenance is never
// reconstructed from the finding's other fields, and message text never
// becomes a target. The caller supplies the inventory the owner resolves
// claims against.
func AdmissionEvidence(f alert.Finding) (admission.ProducerID, admission.EvidenceInput, error) {
	producer := admission.ProducerID(f.Observation.Producer)
	if ProducerWritableLog(producer) {
		return "", admission.EvidenceInput{}, &admission.Error{Reason: admission.ReasonAttribution, Cause: admission.CauseWritableLog, Detail: "the address came from a log line any local user can write"}
	}
	// A known CDN or website-firewall edge carries every visitor behind it:
	// blocking it as one of them is never an automatic response, whatever
	// else is wrong with the finding.
	if mayBeProxyEdge(f.Attribution, producer) && KnownProxyPeer(f.SourceIP, config.Active()) {
		return "", admission.EvidenceInput{}, &admission.Error{Reason: admission.ReasonAttribution, Cause: admission.CauseProxyPeer, Detail: "the address is a known CDN or proxy edge"}
	}
	// When the web server may replace the logged address, only the peer log
	// can verify it. An unknown state is treated the same way.
	// nginx that only takes an address a CDN edge or a trusted proxy vouched
	// for needs no peer log.
	if rw := CurrentHTTPRewrite(); (f.Attribution == admission.AttributionHTTPPeer || f.Attribution == admission.AttributionTrustedHTTPChain) &&
		rw.State != RewriteNone && !NginxRealIPVerified(rw, webTrustedProxies(config.Active())) {
		if err := rewrittenPeerRefusal(f, producer); err != nil {
			return "", admission.EvidenceInput{}, err
		}
	}
	if producer == "" {
		return "", admission.EvidenceInput{}, &admission.Error{Reason: admission.ReasonAttribution, Cause: admission.CauseNoObservation, Detail: "finding has no observation"}
	}
	parser, ok := ProducerParser(producer)
	if !ok {
		return "", admission.EvidenceInput{}, &admission.Error{Reason: admission.ReasonPolicy, Detail: "finding names no registered producer"}
	}
	if !f.Attribution.Valid() {
		return "", admission.EvidenceInput{}, &admission.Error{Reason: admission.ReasonAttribution, Cause: admission.CauseKindNotAllowed, Detail: "no parser vouched for the finding's address"}
	}
	// A client behind a trusted proxy sends no packets to this host, so no
	// response this build applies can contain it.
	if f.Attribution == admission.AttributionTrustedHTTPChain {
		return "", admission.EvidenceInput{}, &admission.Error{Reason: admission.ReasonAttribution, Cause: admission.CauseUnreachable, Detail: "the address is a client behind a trusted proxy"}
	}
	target, err := admission.CanonicalAddress(f.SourceIP, admission.Caps{IPv6: true})
	if err != nil {
		return "", admission.EvidenceInput{}, err
	}
	return producer, admission.EvidenceInput{
		Check: f.Check, FindingID: alert.FindingID(f), Severity: admissionSeverity(f.Severity),
		Observation: admission.ObservationRef{Stream: f.Observation.Stream, Cursor: f.Observation.Cursor, Version: 1},
		ObservedAt:  f.Observation.ObservedAt, Parser: parser, Target: target, Attribution: f.Attribution, Claims: f.Claims, Intel: f.Intel,
	}, nil
}

// rewrittenPeerRefusal refuses an HTTP finding whose logged address the web
// server may have replaced, unless the peer log shows the address connected
// for itself. A client a trusted proxy forwarded is unreachable, one another
// peer chose is forged. A chain, a finding without an observation, and an
// address the peer log does not cover stay unverified.
func rewrittenPeerRefusal(f alert.Finding, producer admission.ProducerID) error {
	if f.Attribution == admission.AttributionHTTPPeer && producer != "" {
		if client, err := netip.ParseAddr(strings.TrimSpace(f.SourceIP)); err == nil {
			switch settledWebPeerVerdict(client, f.Observation.ObservedAt, f.Timestamp) {
			case PeerDirect:
				return nil
			case PeerProxied:
				return &admission.Error{Reason: admission.ReasonAttribution, Cause: admission.CauseUnreachable, Detail: "the peer log shows the address behind a trusted proxy"}
			case PeerForged:
				return &admission.Error{Reason: admission.ReasonAttribution, Cause: admission.CauseForgedClient, Detail: "the peer log shows another peer chose the address"}
			}
		}
	}
	return &admission.Error{Reason: admission.ReasonAttribution, Cause: admission.CauseRewrittenLog, Detail: "the web server may replace the client address it logs"}
}

// mayBeProxyEdge reports whether a finding's address can be an edge that
// relays other people's requests: an HTTP peer or forwarded address, a
// cpsrvd peer (CDNs proxy the cPanel ports), a Stalwart peer (CDNs can proxy
// mail ports), or reputation intel resting on such a sighting.
func mayBeProxyEdge(kind admission.Attribution, producer admission.ProducerID) bool {
	switch kind {
	case admission.AttributionHTTPPeer, admission.AttributionTrustedHTTPChain, admission.AttributionDerived:
		return true
	case admission.AttributionPeer:
		return producer == ProducerCpanelAccessLog || producer == ProducerCpanelScan || producer == ProducerStalwartLog
	}
	return false
}

// AdmissionTarget is the canonical target of a response: an address, or a
// prefix when the funnel acts on a subnet.
func AdmissionTarget(raw string, caps admission.Caps) (admission.Target, error) {
	if strings.Contains(raw, "/") {
		return admission.CanonicalPrefix(raw, caps)
	}
	return admission.CanonicalAddress(raw, caps)
}

// AdmissionSeverity is the admission severity of an alert severity.
func AdmissionSeverity(s alert.Severity) admission.Severity { return admissionSeverity(s) }

// webTrustedProxies is web_server.trusted_proxies, or nothing without a
// configuration.
func webTrustedProxies(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	return cfg.WebServer.TrustedProxies
}
