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

// Package convert implements offline translation of third-party network policy
// formats into Calico's policy model. The only source format supported today is
// Cilium (CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy).
package convert

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The Cilium policy kinds we accept as input.
const (
	KindCiliumNetworkPolicy            = "CiliumNetworkPolicy"
	KindCiliumClusterwideNetworkPolicy = "CiliumClusterwideNetworkPolicy"
)

// The structs below are a hand-maintained, trimmed transcription of the Cilium
// v2 policy CRDs (github.com/cilium/cilium/pkg/policy/api). We model the full
// set of documented rule fields — including ones we cannot convert — so that
// strict decoding rejects genuinely unknown fields (no silent gaps) while the
// converter can give a precise error for known-but-unsupported constructs.

// CiliumNetworkPolicy is a namespaced Cilium policy. It carries either a single
// rule in Spec or a list of rules in Specs (at least one is set).
type CiliumNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec  *Rule   `json:"spec,omitempty"`
	Specs []*Rule `json:"specs,omitempty"`
}

// CiliumClusterwideNetworkPolicy is the cluster-scoped counterpart. The rule
// body is identical to CiliumNetworkPolicy.
type CiliumClusterwideNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec  *Rule   `json:"spec,omitempty"`
	Specs []*Rule `json:"specs,omitempty"`
}

// Rule is a single Cilium policy rule.
type Rule struct {
	EndpointSelector *metav1.LabelSelector `json:"endpointSelector,omitempty"`
	NodeSelector     *metav1.LabelSelector `json:"nodeSelector,omitempty"`

	Ingress     []IngressRule     `json:"ingress,omitempty"`
	IngressDeny []IngressDenyRule `json:"ingressDeny,omitempty"`
	Egress      []EgressRule      `json:"egress,omitempty"`
	EgressDeny  []EgressDenyRule  `json:"egressDeny,omitempty"`

	// EnableDefaultDeny lets a Cilium user opt out of the implicit default-deny
	// that selecting an endpoint normally creates. Calico has no equivalent
	// knob, so an explicit "false" is rejected by the converter.
	EnableDefaultDeny *DefaultDenyConfig `json:"enableDefaultDeny,omitempty"`

	// Informational only — not converted.
	Labels      []CiliumLabel `json:"labels,omitempty"`
	Description string        `json:"description,omitempty"`
}

// DefaultDenyConfig mirrors Cilium's enableDefaultDeny block.
type DefaultDenyConfig struct {
	Ingress *bool `json:"ingress,omitempty"`
	Egress  *bool `json:"egress,omitempty"`
}

// CiliumLabel is a Cilium metadata label. Carried only so strict decoding does
// not reject it; not used in conversion.
type CiliumLabel struct {
	Key    string `json:"key,omitempty"`
	Value  string `json:"value,omitempty"`
	Source string `json:"source,omitempty"`
}

// IngressRule selects allowed inbound traffic.
type IngressRule struct {
	FromEndpoints []metav1.LabelSelector `json:"fromEndpoints,omitempty"`
	FromRequires  []metav1.LabelSelector `json:"fromRequires,omitempty"`
	FromCIDR      []string               `json:"fromCIDR,omitempty"`
	FromCIDRSet   []CIDRRule             `json:"fromCIDRSet,omitempty"`
	FromEntities  []string               `json:"fromEntities,omitempty"`
	FromGroups    []GroupRule            `json:"fromGroups,omitempty"`
	FromNodes     []metav1.LabelSelector `json:"fromNodes,omitempty"`

	ToPorts        []PortRule      `json:"toPorts,omitempty"`
	ICMPs          []ICMPRule      `json:"icmps,omitempty"`
	Authentication *Authentication `json:"authentication,omitempty"`
}

// IngressDenyRule selects denied inbound traffic. It has no L7 port rules.
type IngressDenyRule struct {
	FromEndpoints []metav1.LabelSelector `json:"fromEndpoints,omitempty"`
	FromRequires  []metav1.LabelSelector `json:"fromRequires,omitempty"`
	FromCIDR      []string               `json:"fromCIDR,omitempty"`
	FromCIDRSet   []CIDRRule             `json:"fromCIDRSet,omitempty"`
	FromEntities  []string               `json:"fromEntities,omitempty"`
	FromGroups    []GroupRule            `json:"fromGroups,omitempty"`
	FromNodes     []metav1.LabelSelector `json:"fromNodes,omitempty"`

	ToPorts []PortDenyRule `json:"toPorts,omitempty"`
	ICMPs   []ICMPRule     `json:"icmps,omitempty"`
}

// EgressRule selects allowed outbound traffic.
type EgressRule struct {
	ToEndpoints []metav1.LabelSelector `json:"toEndpoints,omitempty"`
	ToRequires  []metav1.LabelSelector `json:"toRequires,omitempty"`
	ToCIDR      []string               `json:"toCIDR,omitempty"`
	ToCIDRSet   []CIDRRule             `json:"toCIDRSet,omitempty"`
	ToEntities  []string               `json:"toEntities,omitempty"`
	ToServices  []ServiceRule          `json:"toServices,omitempty"`
	ToFQDNs     []FQDNRule             `json:"toFQDNs,omitempty"`
	ToGroups    []GroupRule            `json:"toGroups,omitempty"`
	ToNodes     []metav1.LabelSelector `json:"toNodes,omitempty"`

	ToPorts        []PortRule      `json:"toPorts,omitempty"`
	ICMPs          []ICMPRule      `json:"icmps,omitempty"`
	Authentication *Authentication `json:"authentication,omitempty"`
}

// EgressDenyRule selects denied outbound traffic. It has no L7 port rules.
type EgressDenyRule struct {
	ToEndpoints []metav1.LabelSelector `json:"toEndpoints,omitempty"`
	ToRequires  []metav1.LabelSelector `json:"toRequires,omitempty"`
	ToCIDR      []string               `json:"toCIDR,omitempty"`
	ToCIDRSet   []CIDRRule             `json:"toCIDRSet,omitempty"`
	ToEntities  []string               `json:"toEntities,omitempty"`
	ToServices  []ServiceRule          `json:"toServices,omitempty"`
	ToGroups    []GroupRule            `json:"toGroups,omitempty"`
	ToNodes     []metav1.LabelSelector `json:"toNodes,omitempty"`

	ToPorts []PortDenyRule `json:"toPorts,omitempty"`
	ICMPs   []ICMPRule     `json:"icmps,omitempty"`
}

// CIDRRule is a CIDR with optional exceptions (and, in newer Cilium, a group ref).
type CIDRRule struct {
	Cidr         string   `json:"cidr,omitempty"`
	ExceptCIDRs  []string `json:"except,omitempty"`
	CIDRGroupRef string   `json:"cidrGroupRef,omitempty"`
}

// PortRule is an allowed L4 port set with optional L7 rules.
type PortRule struct {
	Ports []PortProtocol `json:"ports,omitempty"`
	Rules *L7Rules       `json:"rules,omitempty"`

	// TLS / SNI / listener fields are unsupported; modeled for detection only.
	ServerNames    []string    `json:"serverNames,omitempty"`
	TerminatingTLS *TLSContext `json:"terminatingTLS,omitempty"`
	OriginatingTLS *TLSContext `json:"originatingTLS,omitempty"`
	Listener       *Listener   `json:"listener,omitempty"`
}

// PortDenyRule is the L4 port set used in deny rules (no L7).
type PortDenyRule struct {
	Ports []PortProtocol `json:"ports,omitempty"`
}

// PortProtocol is a single port (or port range) and protocol.
type PortProtocol struct {
	Port     string `json:"port,omitempty"`
	EndPort  int32  `json:"endPort,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// L7Rules holds layer-7 match criteria. Only HTTP is partially supported.
type L7Rules struct {
	HTTP    []PortRuleHTTP `json:"http,omitempty"`
	Kafka   []any          `json:"kafka,omitempty"`
	DNS     []any          `json:"dns,omitempty"`
	L7Proto string         `json:"l7proto,omitempty"`
	L7      []any          `json:"l7,omitempty"`
}

// PortRuleHTTP is an L7 HTTP match. Only Method and a literal Path are converted.
type PortRuleHTTP struct {
	Path          string   `json:"path,omitempty"`
	Method        string   `json:"method,omitempty"`
	Host          string   `json:"host,omitempty"`
	Headers       []string `json:"headers,omitempty"`
	HeaderMatches []any    `json:"headerMatches,omitempty"`
}

// ICMPRule is a set of ICMP type matches.
type ICMPRule struct {
	Fields []ICMPField `json:"fields,omitempty"`
}

// ICMPField matches a single ICMP type within a family.
type ICMPField struct {
	Family string `json:"family,omitempty"` // "IPv4" (default) or "IPv6"
	Type   string `json:"type,omitempty"`   // numeric or symbolic
}

// The following types are modeled only so that strict decoding accepts the
// fields and the converter can reject them with a precise message. They are
// intentionally opaque.
type (
	Authentication struct {
		Mode string `json:"mode,omitempty"`
	}
	ServiceRule map[string]any
	FQDNRule    map[string]any
	GroupRule   map[string]any
	TLSContext  map[string]any
	Listener    map[string]any
)
