// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package convert

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

// defaultNamespace is used when a CiliumNetworkPolicy omits metadata.namespace,
// matching kubectl/Cilium behaviour.
const defaultNamespace = "default"

// k8sNamespaceLabel is the reserved Cilium label key (after stripping the source
// prefix) used inside endpoint selectors to match on the pod's namespace.
const k8sNamespaceLabel = "io.kubernetes.pod.namespace"

// k8sNamespaceNameLabel is the well-known Kubernetes namespace label that Calico
// mirrors onto namespace profiles. We target it from converted namespaceSelectors.
const k8sNamespaceNameLabel = "kubernetes.io/metadata.name"

// FromCiliumYAML converts a single YAML/JSON document containing a
// CiliumNetworkPolicy or CiliumClusterwideNetworkPolicy into the equivalent
// Calico resources. It fails (rather than silently dropping) on any Cilium
// construct that cannot be faithfully represented in Calico.
func FromCiliumYAML(doc []byte) ([]runtime.Object, error) {
	var tm metav1.TypeMeta
	if err := yaml.Unmarshal(doc, &tm); err != nil {
		return nil, fmt.Errorf("not a valid YAML/JSON document: %w", err)
	}

	switch tm.Kind {
	case KindCiliumNetworkPolicy:
		var cnp CiliumNetworkPolicy
		if err := yaml.UnmarshalStrict(doc, &cnp); err != nil {
			return nil, fmt.Errorf("%s: %w", KindCiliumNetworkPolicy, err)
		}
		return convertPolicy(cnp.ObjectMeta, cnp.Spec, cnp.Specs, false)
	case KindCiliumClusterwideNetworkPolicy:
		var ccnp CiliumClusterwideNetworkPolicy
		if err := yaml.UnmarshalStrict(doc, &ccnp); err != nil {
			return nil, fmt.Errorf("%s: %w", KindCiliumClusterwideNetworkPolicy, err)
		}
		return convertPolicy(ccnp.ObjectMeta, ccnp.Spec, ccnp.Specs, true)
	case "":
		return nil, fmt.Errorf("document has no 'kind'; expected %s or %s",
			KindCiliumNetworkPolicy, KindCiliumClusterwideNetworkPolicy)
	default:
		return nil, fmt.Errorf("unsupported kind %q; expected %s or %s",
			tm.Kind, KindCiliumNetworkPolicy, KindCiliumClusterwideNetworkPolicy)
	}
}

// convertPolicy turns a Cilium policy's spec/specs into one Calico policy per
// rule. clusterwide selects GlobalNetworkPolicy (true) vs namespaced
// NetworkPolicy (false), which also changes namespace-default semantics.
func convertPolicy(meta metav1.ObjectMeta, spec *Rule, specs []*Rule, clusterwide bool) ([]runtime.Object, error) {
	rules := []*Rule{}
	if spec != nil {
		rules = append(rules, spec)
	}
	rules = append(rules, specs...)
	if len(rules) == 0 {
		return nil, fmt.Errorf("policy %q has neither 'spec' nor 'specs'", meta.Name)
	}

	ns := meta.Namespace
	if !clusterwide && ns == "" {
		ns = defaultNamespace
	}

	var out []runtime.Object
	for i, r := range rules {
		// Name the outputs deterministically. With a single rule keep the
		// original name; with specs, suffix the index to keep them unique.
		name := meta.Name
		if len(rules) > 1 {
			name = fmt.Sprintf("%s-%d", meta.Name, i)
		}

		obj, err := convertRule(name, ns, r, clusterwide)
		if err != nil {
			return nil, fmt.Errorf("policy %q (rule %d): %w", meta.Name, i, err)
		}
		out = append(out, obj)
	}
	return out, nil
}

func convertRule(name, namespace string, r *Rule, clusterwide bool) (runtime.Object, error) {
	if r.NodeSelector != nil {
		return nil, fmt.Errorf("nodeSelector is not supported (host-endpoint policy is out of scope)")
	}
	if r.EnableDefaultDeny != nil {
		if (r.EnableDefaultDeny.Ingress != nil && !*r.EnableDefaultDeny.Ingress) ||
			(r.EnableDefaultDeny.Egress != nil && !*r.EnableDefaultDeny.Egress) {
			return nil, fmt.Errorf("enableDefaultDeny=false has no Calico equivalent")
		}
	}

	// Endpoint selector → policy selector.
	selector, err := endpointSelectorToCalico(r.EndpointSelector)
	if err != nil {
		return nil, fmt.Errorf("endpointSelector: %w", err)
	}

	var ingress, egress []apiv3.Rule
	for i := range r.Ingress {
		rules, err := convertIngress(&r.Ingress[i], apiv3.Allow, clusterwide)
		if err != nil {
			return nil, fmt.Errorf("ingress[%d]: %w", i, err)
		}
		ingress = append(ingress, rules...)
	}
	for i := range r.IngressDeny {
		rules, err := convertIngressDeny(&r.IngressDeny[i], clusterwide)
		if err != nil {
			return nil, fmt.Errorf("ingressDeny[%d]: %w", i, err)
		}
		ingress = append(ingress, rules...)
	}
	for i := range r.Egress {
		rules, err := convertEgress(&r.Egress[i], apiv3.Allow, clusterwide)
		if err != nil {
			return nil, fmt.Errorf("egress[%d]: %w", i, err)
		}
		egress = append(egress, rules...)
	}
	for i := range r.EgressDeny {
		rules, err := convertEgressDeny(&r.EgressDeny[i], clusterwide)
		if err != nil {
			return nil, fmt.Errorf("egressDeny[%d]: %w", i, err)
		}
		egress = append(egress, rules...)
	}

	// Cilium infers policy types from the presence of ingress/egress sections.
	var types []apiv3.PolicyType
	if len(r.Ingress) > 0 || len(r.IngressDeny) > 0 {
		types = append(types, apiv3.PolicyTypeIngress)
	}
	if len(r.Egress) > 0 || len(r.EgressDeny) > 0 {
		types = append(types, apiv3.PolicyTypeEgress)
	}

	if clusterwide {
		gnp := apiv3.NewGlobalNetworkPolicy()
		gnp.Name = name
		gnp.Spec.Selector = selector
		gnp.Spec.Types = types
		gnp.Spec.Ingress = ingress
		gnp.Spec.Egress = egress
		return gnp, nil
	}

	np := apiv3.NewNetworkPolicy()
	np.Name = name
	np.Namespace = namespace
	np.Spec.Selector = selector
	np.Spec.Types = types
	np.Spec.Ingress = ingress
	np.Spec.Egress = egress
	return np, nil
}

// peers describes the set of "other end" EntityRules a direction rule matches,
// derived from the from*/to* fields. Each entry is OR'd with the others.
func convertIngress(in *IngressRule, action apiv3.Action, clusterwide bool) ([]apiv3.Rule, error) {
	if len(in.FromRequires) > 0 {
		return nil, fmt.Errorf("fromRequires is not supported")
	}
	if len(in.FromGroups) > 0 {
		return nil, fmt.Errorf("fromGroups is not supported")
	}
	if len(in.FromNodes) > 0 {
		return nil, fmt.Errorf("fromNodes is not supported")
	}
	if in.Authentication != nil {
		return nil, fmt.Errorf("authentication is not supported")
	}

	peers, err := buildPeers(in.FromEndpoints, in.FromCIDR, in.FromCIDRSet, in.FromEntities, clusterwide)
	if err != nil {
		return nil, err
	}
	l4, err := convertPorts(in.ToPorts, action)
	if err != nil {
		return nil, err
	}
	icmp, err := convertICMPs(in.ICMPs)
	if err != nil {
		return nil, err
	}
	return assembleRules(action, true, peers, l4, icmp), nil
}

func convertIngressDeny(in *IngressDenyRule, clusterwide bool) ([]apiv3.Rule, error) {
	if len(in.FromRequires) > 0 {
		return nil, fmt.Errorf("fromRequires is not supported")
	}
	if len(in.FromGroups) > 0 {
		return nil, fmt.Errorf("fromGroups is not supported")
	}
	if len(in.FromNodes) > 0 {
		return nil, fmt.Errorf("fromNodes is not supported")
	}

	peers, err := buildPeers(in.FromEndpoints, in.FromCIDR, in.FromCIDRSet, in.FromEntities, clusterwide)
	if err != nil {
		return nil, err
	}
	l4, err := convertDenyPorts(in.ToPorts)
	if err != nil {
		return nil, err
	}
	icmp, err := convertICMPs(in.ICMPs)
	if err != nil {
		return nil, err
	}
	return assembleRules(apiv3.Deny, true, peers, l4, icmp), nil
}

func convertEgress(e *EgressRule, action apiv3.Action, clusterwide bool) ([]apiv3.Rule, error) {
	if len(e.ToRequires) > 0 {
		return nil, fmt.Errorf("toRequires is not supported")
	}
	if len(e.ToServices) > 0 {
		return nil, fmt.Errorf("toServices is not supported")
	}
	if len(e.ToFQDNs) > 0 {
		return nil, fmt.Errorf("toFQDNs is not supported")
	}
	if len(e.ToGroups) > 0 {
		return nil, fmt.Errorf("toGroups is not supported")
	}
	if len(e.ToNodes) > 0 {
		return nil, fmt.Errorf("toNodes is not supported")
	}
	if e.Authentication != nil {
		return nil, fmt.Errorf("authentication is not supported")
	}

	peers, err := buildPeers(e.ToEndpoints, e.ToCIDR, e.ToCIDRSet, e.ToEntities, clusterwide)
	if err != nil {
		return nil, err
	}
	l4, err := convertPorts(e.ToPorts, action)
	if err != nil {
		return nil, err
	}
	icmp, err := convertICMPs(e.ICMPs)
	if err != nil {
		return nil, err
	}
	return assembleRules(action, false, peers, l4, icmp), nil
}

func convertEgressDeny(e *EgressDenyRule, clusterwide bool) ([]apiv3.Rule, error) {
	if len(e.ToRequires) > 0 {
		return nil, fmt.Errorf("toRequires is not supported")
	}
	if len(e.ToServices) > 0 {
		return nil, fmt.Errorf("toServices is not supported")
	}
	if len(e.ToGroups) > 0 {
		return nil, fmt.Errorf("toGroups is not supported")
	}
	if len(e.ToNodes) > 0 {
		return nil, fmt.Errorf("toNodes is not supported")
	}

	peers, err := buildPeers(e.ToEndpoints, e.ToCIDR, e.ToCIDRSet, e.ToEntities, clusterwide)
	if err != nil {
		return nil, err
	}
	l4, err := convertDenyPorts(e.ToPorts)
	if err != nil {
		return nil, err
	}
	icmp, err := convertICMPs(e.ICMPs)
	if err != nil {
		return nil, err
	}
	return assembleRules(apiv3.Deny, false, peers, l4, icmp), nil
}

// l4Match is one protocol/port group, optionally carrying an HTTP match.
type l4Match struct {
	protocol *numorstring.Protocol
	ports    []numorstring.Port
	http     *apiv3.HTTPMatch
}

// icmpMatch is one ICMP type match with its protocol (ICMP or ICMPv6).
type icmpMatch struct {
	protocol numorstring.Protocol
	icmp     *apiv3.ICMPFields
}

// assembleRules forms the cross-product of peers × L4/ICMP matches into Calico
// rules. For ingress the peer is the Source; for egress it is the Destination.
// Ports always live on the Destination (they are destination ports either way).
func assembleRules(action apiv3.Action, ingress bool, peers []apiv3.EntityRule, l4 []l4Match, icmp []icmpMatch) []apiv3.Rule {
	if len(peers) == 0 {
		peers = []apiv3.EntityRule{{}}
	}

	var rules []apiv3.Rule
	for _, peer := range peers {
		// No L4/ICMP narrowing: a single rule allowing/denying all traffic
		// to/from the peer.
		if len(l4) == 0 && len(icmp) == 0 {
			rules = append(rules, makeRule(action, ingress, peer, nil, nil, nil, nil))
			continue
		}
		for _, m := range l4 {
			rules = append(rules, makeRule(action, ingress, peer, m.protocol, m.ports, m.http, nil))
		}
		for _, m := range icmp {
			proto := m.protocol
			rules = append(rules, makeRule(action, ingress, peer, &proto, nil, nil, m.icmp))
		}
	}
	return rules
}

func makeRule(action apiv3.Action, ingress bool, peer apiv3.EntityRule, protocol *numorstring.Protocol, ports []numorstring.Port, http *apiv3.HTTPMatch, icmp *apiv3.ICMPFields) apiv3.Rule {
	r := apiv3.Rule{
		Action:   action,
		Protocol: protocol,
		HTTP:     http,
		ICMP:     icmp,
	}
	if ingress {
		r.Source = peer
		r.Destination.Ports = ports
	} else {
		r.Destination = peer
		r.Destination.Ports = ports
	}
	return r
}

// buildPeers converts the L3 selectors of a direction rule into Calico
// EntityRules. Endpoint selectors, CIDR sets and entities each become their own
// (OR'd) peer; bare CIDRs are collapsed into a single Nets list.
func buildPeers(endpoints []metav1.LabelSelector, cidrs []string, cidrSets []CIDRRule, entities []string, clusterwide bool) ([]apiv3.EntityRule, error) {
	var peers []apiv3.EntityRule

	for i := range endpoints {
		sel, nsSel, err := peerSelectorToCalico(&endpoints[i], clusterwide)
		if err != nil {
			return nil, fmt.Errorf("endpoint selector: %w", err)
		}
		peers = append(peers, apiv3.EntityRule{Selector: sel, NamespaceSelector: nsSel})
	}

	// Bare CIDRs collapse into Nets, but Calico forbids mixing IP families in a
	// single rule, so split them into one peer per family.
	if len(cidrs) > 0 {
		v4, v6 := splitByFamily(cidrs)
		if len(v4) > 0 {
			peers = append(peers, apiv3.EntityRule{Nets: v4})
		}
		if len(v6) > 0 {
			peers = append(peers, apiv3.EntityRule{Nets: v6})
		}
	}

	for _, cs := range cidrSets {
		if cs.CIDRGroupRef != "" {
			return nil, fmt.Errorf("cidrGroupRef is not supported")
		}
		if cs.Cidr == "" {
			return nil, fmt.Errorf("CIDRSet entry without a cidr is not supported")
		}
		peers = append(peers, apiv3.EntityRule{
			Nets:    []string{cs.Cidr},
			NotNets: append([]string(nil), cs.ExceptCIDRs...),
		})
	}

	for _, e := range entities {
		entityPeers, err := convertEntity(e)
		if err != nil {
			return nil, err
		}
		peers = append(peers, entityPeers...)
	}

	return peers, nil
}

// convertEntity maps the small set of Cilium reserved entities we can express
// faithfully in OSS Calico. Anything else fails. "world" yields two peers (one
// per IP family) because Calico forbids mixing families in a single rule.
func convertEntity(entity string) ([]apiv3.EntityRule, error) {
	switch strings.ToLower(strings.TrimSpace(entity)) {
	case "all":
		return []apiv3.EntityRule{{}}, nil
	case "world":
		return []apiv3.EntityRule{{Nets: []string{"0.0.0.0/0"}}, {Nets: []string{"::/0"}}}, nil
	case "world-ipv4":
		return []apiv3.EntityRule{{Nets: []string{"0.0.0.0/0"}}}, nil
	case "world-ipv6":
		return []apiv3.EntityRule{{Nets: []string{"::/0"}}}, nil
	default:
		return nil, fmt.Errorf("entity %q has no faithful Calico equivalent", entity)
	}
}

// splitByFamily partitions CIDRs into IPv4 and IPv6, preserving order.
func splitByFamily(cidrs []string) (v4, v6 []string) {
	for _, c := range cidrs {
		if strings.Contains(c, ":") {
			v6 = append(v6, c)
		} else {
			v4 = append(v4, c)
		}
	}
	return v4, v6
}

// convertPorts turns Cilium toPorts (with optional L7 HTTP) into L4 matches.
func convertPorts(toPorts []PortRule, action apiv3.Action) ([]l4Match, error) {
	var matches []l4Match
	for i := range toPorts {
		pr := &toPorts[i]
		if len(pr.ServerNames) > 0 {
			return nil, fmt.Errorf("toPorts[%d].serverNames is not supported", i)
		}
		if pr.TerminatingTLS != nil || pr.OriginatingTLS != nil {
			return nil, fmt.Errorf("toPorts[%d] TLS termination/origination is not supported", i)
		}
		if pr.Listener != nil {
			return nil, fmt.Errorf("toPorts[%d].listener is not supported", i)
		}

		http, err := convertL7(pr.Rules)
		if err != nil {
			return nil, fmt.Errorf("toPorts[%d]: %w", i, err)
		}
		if http != nil && action != apiv3.Allow {
			return nil, fmt.Errorf("toPorts[%d]: HTTP match is only valid on allow rules", i)
		}

		groups, err := portsByProtocol(pr.Ports, http != nil)
		if err != nil {
			return nil, fmt.Errorf("toPorts[%d]: %w", i, err)
		}
		for _, g := range groups {
			matches = append(matches, l4Match{protocol: g.protocol, ports: g.ports, http: http})
		}
	}
	return matches, nil
}

func convertDenyPorts(toPorts []PortDenyRule) ([]l4Match, error) {
	var matches []l4Match
	for i := range toPorts {
		groups, err := portsByProtocol(toPorts[i].Ports, false)
		if err != nil {
			return nil, fmt.Errorf("toPorts[%d]: %w", i, err)
		}
		for _, g := range groups {
			matches = append(matches, l4Match{protocol: g.protocol, ports: g.ports})
		}
	}
	return matches, nil
}

type protoPorts struct {
	protocol *numorstring.Protocol
	ports    []numorstring.Port
}

// portsByProtocol groups a PortRule's ports by protocol, since each Calico rule
// carries a single protocol. Cilium "ANY" expands to TCP+UDP (or just TCP when
// an HTTP match is present, which is TCP-only). A PortRule with no ports yields
// a single group with no protocol.
func portsByProtocol(ports []PortProtocol, hasHTTP bool) ([]protoPorts, error) {
	if len(ports) == 0 {
		return []protoPorts{{}}, nil
	}

	// Preserve a stable protocol ordering for deterministic output.
	order := []string{}
	byProto := map[string][]numorstring.Port{}
	add := func(proto string, p numorstring.Port) {
		if _, ok := byProto[proto]; !ok {
			order = append(order, proto)
		}
		byProto[proto] = append(byProto[proto], p)
	}

	for _, pp := range ports {
		port, err := parsePort(pp)
		if err != nil {
			return nil, err
		}
		protocols, err := protocolsFor(pp.Protocol, hasHTTP)
		if err != nil {
			return nil, err
		}
		for _, proto := range protocols {
			add(proto, port)
		}
	}

	var out []protoPorts
	for _, proto := range order {
		p := numorstring.ProtocolFromString(proto)
		out = append(out, protoPorts{protocol: &p, ports: byProto[proto]})
	}
	return out, nil
}

// protocolsFor maps a Cilium protocol string to the Calico protocol(s) to emit.
func protocolsFor(proto string, hasHTTP bool) ([]string, error) {
	switch strings.ToUpper(strings.TrimSpace(proto)) {
	case "", "ANY":
		if hasHTTP {
			return []string{numorstring.ProtocolTCP}, nil
		}
		return []string{numorstring.ProtocolTCP, numorstring.ProtocolUDP}, nil
	case "TCP":
		return []string{numorstring.ProtocolTCP}, nil
	case "UDP":
		if hasHTTP {
			return nil, fmt.Errorf("HTTP match requires protocol TCP, got UDP")
		}
		return []string{numorstring.ProtocolUDP}, nil
	case "SCTP":
		if hasHTTP {
			return nil, fmt.Errorf("HTTP match requires protocol TCP, got SCTP")
		}
		return []string{numorstring.ProtocolSCTP}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol %q", proto)
	}
}

func parsePort(pp PortProtocol) (numorstring.Port, error) {
	if pp.Port == "" {
		return numorstring.Port{}, fmt.Errorf("port entry without a port number")
	}
	if pp.EndPort != 0 {
		min, err := strconv.ParseUint(pp.Port, 10, 16)
		if err != nil {
			return numorstring.Port{}, fmt.Errorf("port range start %q must be numeric: %w", pp.Port, err)
		}
		if pp.EndPort < 0 || pp.EndPort > 65535 {
			return numorstring.Port{}, fmt.Errorf("endPort %d out of range", pp.EndPort)
		}
		return numorstring.PortFromRange(uint16(min), uint16(pp.EndPort))
	}
	// Single numeric or named port.
	return numorstring.PortFromString(pp.Port)
}

// convertL7 converts the HTTP portion of Cilium L7 rules. Any other L7 protocol
// (Kafka, DNS, generic Envoy) or unsupported HTTP feature fails.
func convertL7(rules *L7Rules) (*apiv3.HTTPMatch, error) {
	if rules == nil {
		return nil, nil
	}
	if len(rules.Kafka) > 0 {
		return nil, fmt.Errorf("Kafka L7 rules are not supported")
	}
	if len(rules.DNS) > 0 {
		return nil, fmt.Errorf("DNS L7 rules are not supported")
	}
	if rules.L7Proto != "" || len(rules.L7) > 0 {
		return nil, fmt.Errorf("generic L7 (%q) rules are not supported", rules.L7Proto)
	}
	if len(rules.HTTP) == 0 {
		return nil, nil
	}

	match := &apiv3.HTTPMatch{}
	methods := map[string]bool{}
	for _, h := range rules.HTTP {
		if h.Host != "" {
			return nil, fmt.Errorf("HTTP host match is not supported")
		}
		if len(h.Headers) > 0 || len(h.HeaderMatches) > 0 {
			return nil, fmt.Errorf("HTTP header match is not supported")
		}
		if h.Method != "" && !methods[h.Method] {
			methods[h.Method] = true
			match.Methods = append(match.Methods, h.Method)
		}
		if h.Path != "" {
			p, err := convertHTTPPath(h.Path)
			if err != nil {
				return nil, err
			}
			match.Paths = append(match.Paths, p)
		}
	}
	sort.Strings(match.Methods)
	return match, nil
}

// convertHTTPPath maps a Cilium HTTP path (a regular expression) to a Calico
// exact or prefix match, but only when it is a plain literal — Calico does not
// support regex paths, so anything with regex metacharacters fails rather than
// silently changing the match semantics.
func convertHTTPPath(path string) (apiv3.HTTPPath, error) {
	// A trailing ".*" on an otherwise-literal path is the common Cilium idiom
	// for a prefix match; translate that to a Calico prefix.
	if literal, ok := strings.CutSuffix(path, ".*"); ok {
		if isLiteralPath(literal) {
			return apiv3.HTTPPath{Prefix: literal}, nil
		}
	}
	if isLiteralPath(path) {
		return apiv3.HTTPPath{Exact: path}, nil
	}
	return apiv3.HTTPPath{}, fmt.Errorf("HTTP path %q is a regular expression; only literal exact/prefix paths are supported", path)
}

// isLiteralPath reports whether s contains no regex metacharacters, so it can be
// treated as an exact/prefix literal.
func isLiteralPath(s string) bool {
	return !strings.ContainsAny(s, `.*+?()[]{}|^$\`)
}

// convertICMPs maps Cilium ICMP type matches to Calico ICMP rules.
func convertICMPs(icmps []ICMPRule) ([]icmpMatch, error) {
	var matches []icmpMatch
	for _, rule := range icmps {
		for _, f := range rule.Fields {
			proto, err := icmpProtocolFor(f.Family)
			if err != nil {
				return nil, err
			}
			fields := &apiv3.ICMPFields{}
			if f.Type != "" {
				t, err := strconv.Atoi(f.Type)
				if err != nil {
					return nil, fmt.Errorf("ICMP type %q must be numeric; symbolic names are not supported", f.Type)
				}
				fields.Type = &t
			}
			matches = append(matches, icmpMatch{protocol: proto, icmp: fields})
		}
	}
	return matches, nil
}

func icmpProtocolFor(family string) (numorstring.Protocol, error) {
	switch strings.ToLower(strings.TrimSpace(family)) {
	case "", "ipv4":
		return numorstring.ProtocolFromString("ICMP"), nil
	case "ipv6":
		return numorstring.ProtocolFromString("ICMPv6"), nil
	default:
		return numorstring.Protocol{}, fmt.Errorf("unknown ICMP family %q", family)
	}
}

// endpointSelectorToCalico converts a Cilium endpointSelector (which applies to
// the policy's own endpoints) into a Calico policy selector. An empty/nil
// selector matches all endpoints in scope, i.e. "all()".
func endpointSelectorToCalico(sel *metav1.LabelSelector) (string, error) {
	if sel == nil {
		return "all()", nil
	}
	expr, err := labelSelectorToExpr(sel)
	if err != nil {
		return "", err
	}
	if expr == "" {
		return "all()", nil
	}
	return expr, nil
}

// peerSelectorToCalico converts a Cilium from/to endpoint selector into a Calico
// (selector, namespaceSelector) pair. The reserved pod-namespace label is lifted
// into the namespaceSelector. An empty selector matches all endpoints in scope.
func peerSelectorToCalico(sel *metav1.LabelSelector, clusterwide bool) (selector, namespaceSelector string, err error) {
	// Defaults preserve Cilium's namespace scoping: namespaced policies match
	// within the policy's namespace (empty namespaceSelector); clusterwide
	// policies match across all namespaces (all()).
	if clusterwide {
		namespaceSelector = "all()"
	}
	if sel == nil {
		return "all()", namespaceSelector, nil
	}

	// Split off the reserved namespace label(s) into the namespace selector.
	remaining, nsSel, err := extractNamespaceSelector(sel, clusterwide)
	if err != nil {
		return "", "", err
	}

	expr, err := labelSelectorToExpr(remaining)
	if err != nil {
		return "", "", err
	}
	if expr == "" {
		expr = "all()"
	}
	return expr, nsSel, nil
}

// extractNamespaceSelector pulls any pod-namespace label out of sel and returns
// the remaining selector plus a Calico namespaceSelector targeting the namespace
// name label. The default namespaceSelector is returned when no namespace label
// is present.
func extractNamespaceSelector(sel *metav1.LabelSelector, clusterwide bool) (*metav1.LabelSelector, string, error) {
	defaultNS := ""
	if clusterwide {
		defaultNS = "all()"
	}

	remaining := &metav1.LabelSelector{}
	nsExprs := []string{}

	keys := make([]string, 0, len(sel.MatchLabels))
	for k := range sel.MatchLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		norm, err := normalizeLabelKey(k)
		if err != nil {
			return nil, "", err
		}
		if norm == k8sNamespaceLabel {
			nsExprs = append(nsExprs, fmt.Sprintf("%s == '%s'", k8sNamespaceNameLabel, sel.MatchLabels[k]))
			continue
		}
		if remaining.MatchLabels == nil {
			remaining.MatchLabels = map[string]string{}
		}
		remaining.MatchLabels[norm] = sel.MatchLabels[k]
	}

	for _, e := range sel.MatchExpressions {
		norm, err := normalizeLabelKey(e.Key)
		if err != nil {
			return nil, "", err
		}
		if norm == k8sNamespaceLabel {
			expr, err := matchExpressionToCalico(k8sNamespaceNameLabel, e)
			if err != nil {
				return nil, "", err
			}
			nsExprs = append(nsExprs, expr)
			continue
		}
		ne := e
		ne.Key = norm
		remaining.MatchExpressions = append(remaining.MatchExpressions, ne)
	}

	if len(nsExprs) == 0 {
		return remaining, defaultNS, nil
	}
	return remaining, strings.Join(nsExprs, " && "), nil
}

// labelSelectorToExpr renders a label selector as a Calico selector expression,
// after normalizing each label key. An empty selector renders as "".
func labelSelectorToExpr(sel *metav1.LabelSelector) (string, error) {
	if sel == nil {
		return "", nil
	}

	var exprs []string

	keys := make([]string, 0, len(sel.MatchLabels))
	for k := range sel.MatchLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		norm, err := normalizeLabelKey(k)
		if err != nil {
			return "", err
		}
		exprs = append(exprs, fmt.Sprintf("%s == '%s'", norm, sel.MatchLabels[k]))
	}

	for _, e := range sel.MatchExpressions {
		norm, err := normalizeLabelKey(e.Key)
		if err != nil {
			return "", err
		}
		expr, err := matchExpressionToCalico(norm, e)
		if err != nil {
			return "", err
		}
		exprs = append(exprs, expr)
	}

	return strings.Join(exprs, " && "), nil
}

func matchExpressionToCalico(key string, e metav1.LabelSelectorRequirement) (string, error) {
	switch e.Operator {
	case metav1.LabelSelectorOpIn:
		return fmt.Sprintf("%s in { '%s' }", key, strings.Join(e.Values, "', '")), nil
	case metav1.LabelSelectorOpNotIn:
		return fmt.Sprintf("%s not in { '%s' }", key, strings.Join(e.Values, "', '")), nil
	case metav1.LabelSelectorOpExists:
		return fmt.Sprintf("has(%s)", key), nil
	case metav1.LabelSelectorOpDoesNotExist:
		return fmt.Sprintf("! has(%s)", key), nil
	default:
		return "", fmt.Errorf("unsupported match expression operator %q", e.Operator)
	}
}

// normalizeLabelKey strips Cilium's source prefix ("k8s:"/"any:") from a label
// key and rejects keys that encode reserved identities or namespace-label
// matches, which Cilium expresses as labels but Calico cannot represent here.
func normalizeLabelKey(key string) (string, error) {
	k := key
	switch {
	case strings.HasPrefix(k, "k8s:"):
		k = strings.TrimPrefix(k, "k8s:")
	case strings.HasPrefix(k, "any:"):
		k = strings.TrimPrefix(k, "any:")
	case strings.HasPrefix(k, "reserved:"):
		return "", fmt.Errorf("reserved label %q must be expressed as a Cilium entity, which is handled separately", key)
	}
	if strings.HasPrefix(k, "io.cilium.k8s.namespace.labels.") {
		return "", fmt.Errorf("matching namespaces by label (%q) is not supported", key)
	}
	return k, nil
}
