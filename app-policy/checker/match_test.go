// Copyright (c) 2018-2024 Tigera, Inc. All rights reserved.

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

package checker

import (
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/app-policy/checker/mocks"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	libnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	socketAddressProtocolTCP = &core.Address{
		Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				Protocol: core.SocketAddress_TCP,
			},
		},
	}

	socketAddressProtocolUDP = &core.Address{
		Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				Protocol: core.SocketAddress_UDP,
			},
		},
	}
)

// If no service account names are given, the clause matches any name.
func TestMatchName(t *testing.T) {
	testCases := []struct {
		title  string
		names  []string
		name   string
		result bool
	}{
		{"empty", []string{}, "reginald", true},
		{"match", []string{"susan", "jim", "reginald"}, "reginald", true},
		{"no match", []string{"susan", "jim", "reginald"}, "steven", false},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)
			result := matchName(tc.names, tc.name)
			Expect(result).To(Equal(tc.result))
		})
	}
}

// An empty label selector matches any set of labels.
func TestMatchLabels(t *testing.T) {
	testCases := []struct {
		title    string
		selector string
		labels   map[string]string
		result   bool
	}{
		{"empty", "", map[string]string{"app": "foo", "env": "prod"}, true},
		{"bad selector", "not.a.real.selector", map[string]string{"app": "foo", "env": "prod"}, false},
		{"good selector", "app == 'foo'", map[string]string{"app": "foo", "env": "prod"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)
			result := matchLabels(tc.selector, tc.labels)
			Expect(result).To(Equal(tc.result))
		})
	}
}

// HTTP Methods clause with empty list will match any method.
func TestMatchHTTPMethods(t *testing.T) {
	testCases := []struct {
		title   string
		methods []string
		method  string
		result  bool
	}{
		{"empty", []string{}, "GET", true},
		{"match", []string{"GET", "HEAD"}, "GET", true},
		// HTTP methods are case-sensitive. https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
		{"case-sensitive", []string{"get", "HEAD"}, "GET", false},
		{"wildcard", []string{"*"}, "MADNESS", true},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)
			Expect(matchHTTPMethods(tc.methods, &tc.method)).To(Equal(tc.result))
		})
	}
}

// HTTP Paths clause with empty list will match any path.
func TestMatchHTTPPaths(t *testing.T) {
	testCases := []struct {
		title   string
		paths   []*proto.HTTPMatch_PathMatch
		reqPath string
		result  bool
	}{
		{"empty", []*proto.HTTPMatch_PathMatch{}, "/foo", true},
		{"exact", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}, "/foo", true},
		{"prefix", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/foo"}}}, "/foobar", true},
		{"exact fail", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}, "/joo", false},
		{"exact not match prefix", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}, "/foobar", false},
		{"prefix fail", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/foo"}}}, "/joobar", false},
		{"multiple", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/joo"}}, {PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}, "/joobar", true},
		{"exact path with query", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}, "/foo?xyz", true},
		{"exact path with fragment", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}, "/foo#xyz", true},
		{"prefix path with query fail", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/foobar"}}}, "/foo?bar", false},
		{"prefix path with fragment fail", []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/foobar"}}}, "/foo#bar", false},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)
			Expect(matchHTTPPaths(tc.paths, &tc.reqPath)).To(Equal(tc.result))
		})
	}
}

// An omitted HTTP Match clause always matches.
func TestMatchHTTPNil(t *testing.T) {
	RegisterTestingT(t)

	Expect(matchHTTP(nil, nil, nil)).To(BeTrue())
}

// Test HTTPPaths panic on invalid data.
func TestPanicHTTPPaths(t *testing.T) {
	RegisterTestingT(t)

	defer func() {
		Expect(recover()).To(BeAssignableToTypeOf(&InvalidDataFromDataPlane{}))
	}()
	paths := []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}}}
	reqPath := "foo"
	matchHTTPPaths(paths, &reqPath)
}

// Matching a whole rule should require matching all subclauses.
func TestMatchRule(t *testing.T) {
	RegisterTestingT(t)
	srcAddr := "192.168.4.22"
	dstAddr := "10.54.44.23"

	rule := &proto.Rule{
		SrcServiceAccountMatch: &proto.ServiceAccountMatch{
			Names: []string{"john", "stevie", "sam"},
		},
		DstServiceAccountMatch: &proto.ServiceAccountMatch{
			Names: []string{"ian"},
		},
		SrcIpSetIds:    []string{"src0", "src1"},
		NotSrcIpSetIds: []string{"notSrc0", "notSrc1"},
		DstIpSetIds:    []string{"dst0", "dst1"},
		NotDstIpSetIds: []string{"notDst0", "notDst1"},

		HttpMatch: &proto.HTTPMatch{
			Methods: []string{"GET", "POST"},
			Paths:   []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/path"}}, {PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/pathlong"}}},
		},
		Protocol: &proto.Protocol{
			NumberOrName: &proto.Protocol_Name{
				Name: "TCP",
			},
		},
		SrcPorts: []*proto.PortRange{
			{First: 8458, Last: 8460},
			{First: 12, Last: 12},
		},
		DstPorts: []*proto.PortRange{
			{First: 76, Last: 80},
			{First: 70, Last: 79},
		},
		SrcNet: []string{"192.168.4.0/24"},
		DstNet: []string{"10.54.0.0/16"},
	}
	req := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sam",
			Address: &core.Address{Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Address:       srcAddr,
					Protocol:      core.SocketAddress_TCP,
					PortSpecifier: &core.SocketAddress_PortValue{PortValue: 8458},
				}}},
		},
		Destination: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/ian",
			Address: &core.Address{Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Address:       dstAddr,
					Protocol:      core.SocketAddress_TCP,
					PortSpecifier: &core.SocketAddress_PortValue{PortValue: 80},
				}}},
		},
		Request: &auth.AttributeContext_Request{
			Http: &auth.AttributeContext_HttpRequest{
				Method: "GET",
				Path:   "/path",
			},
		},
	}}

	store := policystore.NewPolicyStore()
	addIPSet(store, "src0", srcAddr)
	addIPSet(store, "src1", srcAddr, dstAddr)
	addIPSet(store, "notSrc0", "5.6.7.8", dstAddr)
	addIPSet(store, "notSrc1", "5.6.7.8")
	addIPSet(store, "dst0", dstAddr)
	addIPSet(store, "dst1", srcAddr, dstAddr)
	addIPSet(store, "notDst0", "5.6.7.8")
	addIPSet(store, "notDst1", "5.6.7.8", srcAddr)

	flow := NewCheckRequestToFlowAdapter(req)
	reqCache := NewRequestCache(store, flow)
	Expect(match("", rule, reqCache)).To(BeTrue())

	// SrcServiceAccountMatch
	ossan := rule.SrcServiceAccountMatch.Names
	rule.SrcServiceAccountMatch.Names = []string{"wendy"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.SrcServiceAccountMatch.Names = ossan
	Expect(match("", rule, reqCache)).To(BeTrue())

	// DstServiceAccountMatch
	odsan := rule.DstServiceAccountMatch.Names
	rule.DstServiceAccountMatch.Names = []string{"wendy"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.DstServiceAccountMatch.Names = odsan
	Expect(match("", rule, reqCache)).To(BeTrue())

	// SrcIpSetIds
	osipi := rule.SrcIpSetIds
	rule.SrcIpSetIds = []string{"notSrc0"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.SrcIpSetIds = osipi
	Expect(match("", rule, reqCache)).To(BeTrue())

	// DstIpSetIds
	odipi := rule.DstIpSetIds
	rule.DstIpSetIds = []string{"notDst0"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.DstIpSetIds = odipi
	Expect(match("", rule, reqCache)).To(BeTrue())

	// NotSrcIpSetIds
	onsipi := rule.NotSrcIpSetIds
	rule.NotSrcIpSetIds = []string{"src0"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.NotSrcIpSetIds = onsipi
	Expect(match("", rule, reqCache)).To(BeTrue())

	// NotDstIpSetIds
	ondipi := rule.NotDstIpSetIds
	rule.NotDstIpSetIds = []string{"dst0"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.NotDstIpSetIds = ondipi
	Expect(match("", rule, reqCache)).To(BeTrue())

	// HTTPMatch
	ohm := rule.HttpMatch.Methods
	rule.HttpMatch.Methods = []string{"HEAD"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.HttpMatch.Methods = ohm
	Expect(match("", rule, reqCache)).To(BeTrue())

	// HTTPPath
	ohp := rule.HttpMatch.Paths
	rule.HttpMatch.Paths = []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/nopath"}}}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.HttpMatch.Paths = ohp
	Expect(match("", rule, reqCache)).To(BeTrue())

	// Protocol
	op := rule.Protocol.GetName()
	rule.Protocol.NumberOrName = &proto.Protocol_Name{Name: "UDP"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.Protocol.NumberOrName = &proto.Protocol_Name{Name: op}
	Expect(match("", rule, reqCache)).To(BeTrue())

	// SrcPorts
	osp := rule.SrcPorts
	rule.SrcPorts = []*proto.PortRange{{First: 25, Last: 25}}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.SrcPorts = osp
	Expect(match("", rule, reqCache)).To(BeTrue())

	// DstPorts
	odp := rule.DstPorts
	rule.DstPorts = []*proto.PortRange{{First: 25, Last: 25}}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.DstPorts = odp
	Expect(match("", rule, reqCache)).To(BeTrue())

	// SrcNet
	osn := rule.SrcNet
	rule.SrcNet = []string{"30.0.0.0/8"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.SrcNet = osn
	Expect(match("", rule, reqCache)).To(BeTrue())

	// DstNet
	odn := rule.DstNet
	rule.DstNet = []string{"30.0.0.0/8"}
	Expect(match("", rule, reqCache)).To(BeFalse())
	rule.DstNet = odn
	Expect(match("", rule, reqCache)).To(BeTrue())
}

// Test namespace selectors are handled correctly
func TestMatchRuleNamespaceSelectors(t *testing.T) {
	RegisterTestingT(t)

	rule := &proto.Rule{
		OriginalSrcNamespaceSelector: "place == 'src'",
		OriginalDstNamespaceSelector: "place == 'dst'",
	}
	req := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/src/sa/sam",
		},
		Destination: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/dst/sa/ian",
		},
		Request: &auth.AttributeContext_Request{
			Http: &auth.AttributeContext_HttpRequest{
				Method: "GET",
			},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)

	store := policystore.NewPolicyStore()
	id := proto.NamespaceID{Name: "src"}
	store.NamespaceByID[types.ProtoToNamespaceID(&id)] = &proto.NamespaceUpdate{Id: &id, Labels: map[string]string{"place": "src"}}
	id = proto.NamespaceID{Name: "dst"}
	store.NamespaceByID[types.ProtoToNamespaceID(&id)] = &proto.NamespaceUpdate{Id: &id, Labels: map[string]string{"place": "dst"}}
	reqCache := NewRequestCache(store, flow)
	Expect(match("", rule, reqCache)).To(BeTrue())
}

// Test that rules only match same namespace if pod selector or service account is set
func TestMatchRulePolicyNamespace(t *testing.T) {
	RegisterTestingT(t)

	req := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/sam",
		},
		Destination: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/ian",
		},
		Request: &auth.AttributeContext_Request{
			Http: &auth.AttributeContext_HttpRequest{
				Method: "GET",
			},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)

	store := policystore.NewPolicyStore()
	reqCache := NewRequestCache(store, flow)

	// With pod selector
	rule := &proto.Rule{
		OriginalSrcSelector: "has(app)",
	}
	Expect(match("different", rule, reqCache)).To(BeFalse())
	Expect(match("testns", rule, reqCache)).To(BeTrue())

	// With no pod selector or SA selector
	rule.OriginalSrcSelector = ""
	Expect(match("different", rule, reqCache)).To(BeTrue())

	// With SA selector
	rule.SrcServiceAccountMatch = &proto.ServiceAccountMatch{Names: []string{"sam"}}
	Expect(match("different", rule, reqCache)).To(BeFalse())
	Expect(match("testns", rule, reqCache)).To(BeTrue())
}

func addIPSet(store *policystore.PolicyStore, id string, addr ...string) {
	s := policystore.NewIPSet(proto.IPSetUpdate_IP)
	for _, a := range addr {
		s.AddString(a)
	}
	store.IPSetByID[id] = s
}

// Test that rules match L4 protocol.
func TestMatchL4Protocol(t *testing.T) {
	RegisterTestingT(t)

	req := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/sam",
		},
		Destination: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/ian",
		},
		Request: &auth.AttributeContext_Request{
			Http: &auth.AttributeContext_HttpRequest{
				Method: "GET",
			},
		},
	}}
	flow := NewCheckRequestToFlowAdapter(req)

	store := policystore.NewPolicyStore()
	reqCache := NewRequestCache(store, flow)

	// With empty rule and default request.
	rule := &proto.Rule{}
	Expect(match("testns", rule, reqCache)).To(BeTrue())

	// With empty rule and UDP request
	req.GetAttributes().GetDestination().Address = socketAddressProtocolUDP
	Expect(match("testns", rule, reqCache)).To(BeTrue())
	req.GetAttributes().GetDestination().Address = nil

	// With Protocol=TCP rule and default request
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "TCP",
		},
	}
	Expect(match("testns", rule, reqCache)).To(BeTrue())
	rule.Protocol = nil

	// With Protocol=6 rule and default request
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 6,
		},
	}
	Expect(match("testns", rule, reqCache)).To(BeTrue())
	rule.Protocol = nil

	// With Protocol=17 rule and default request
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 17,
		},
	}
	Expect(match("testns", rule, reqCache)).To(BeFalse())
	rule.Protocol = nil

	// With Protocol!=UDP rule and default request
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "UDP",
		},
	}
	Expect(match("testns", rule, reqCache)).To(BeTrue())
	rule.NotProtocol = nil

	// With Protocol!=6 rule and TCP request
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{
			Number: 6,
		},
	}
	req.GetAttributes().GetDestination().Address = socketAddressProtocolTCP
	Expect(match("testns", rule, reqCache)).To(BeFalse())
	req.GetAttributes().GetDestination().Address = nil
	rule.NotProtocol = nil

	// With Protocol!=TCP and Protocol == TCP rule and TCP request
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "TCP",
		},
	}
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "TCP",
		},
	}
	req.GetAttributes().GetDestination().Address = socketAddressProtocolTCP
	Expect(match("testns", rule, reqCache)).To(BeFalse())
	req.GetAttributes().GetDestination().Address = nil
	rule.NotProtocol = nil

	// With Protocol!=TCP and Protocol == TCP rule and UDP request
	rule.NotProtocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "TCP",
		},
	}
	rule.Protocol = &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{
			Name: "TCP",
		},
	}
	req.GetAttributes().GetDestination().Address = socketAddressProtocolUDP
	Expect(match("testns", rule, reqCache)).To(BeFalse())
	req.GetAttributes().GetDestination().Address = nil
	rule.NotProtocol = nil
}

/*func TestMatchPort(t *testing.T) {

	testCases := []struct {
		title    string
		ranges   []*proto.PortRange
		ipSetIds []string
		ip       string
		port     int
		match    bool
	}{
		{
			title:    "empty match",
			ranges:   nil,
			ipSetIds: nil,
			ip:       "192.168.4.5",
			port:     12,
			match:    true,
		},
		{
			title:    "single numeric port match",
			ranges:   []*proto.PortRange{{First: 12, Last: 12}},
			ipSetIds: nil,
			ip:       "192.168.4.5",
			port:     12,
			match:    true,
		},
		{
			title:    "single numeric range match",
			ranges:   []*proto.PortRange{{First: 10, Last: 20}},
			ipSetIds: nil,
			ip:       "192.168.4.5",
			port:     13,
			match:    true,
		},
		{
			title:    "single numeric port no match",
			ranges:   []*proto.PortRange{{First: 12, Last: 12}},
			ipSetIds: nil,
			ip:       "192.168.4.5",
			port:     11,
			match:    false,
		},
		{
			title:    "single numeric range no match",
			ranges:   []*proto.PortRange{{First: 10, Last: 20}},
			ipSetIds: nil,
			ip:       "192.168.4.5",
			port:     21,
			match:    false,
		},
		{
			title:    "range lower inclusive",
			ranges:   []*proto.PortRange{{First: 10, Last: 20}},
			ipSetIds: nil,
			ip:       "192.168.4.5",
			port:     10,
			match:    true,
		},
		{
			title:    "range upper inclusive",
			ranges:   []*proto.PortRange{{First: 10, Last: 20}},
			ipSetIds: nil,
			ip:       "192.168.4.5",
			port:     20,
			match:    true,
		},
		{
			title:    "range overlapping in both",
			ranges:   []*proto.PortRange{{First: 10, Last: 20}, {First: 15, Last: 25}},
			ipSetIds: nil,
			ip:       "192.168.4.5",
			port:     19,
			match:    true,
		},
		{
			title:    "range overlapping in one",
			ranges:   []*proto.PortRange{{First: 10, Last: 20}, {First: 15, Last: 25}},
			ipSetIds: nil,
			ip:       "192.168.4.5",
			port:     11,
			match:    true,
		},
		{
			title:    "range overlapping in none",
			ranges:   []*proto.PortRange{{First: 10, Last: 20}, {First: 15, Last: 25}},
			ipSetIds: nil,
			ip:       "192.168.4.5",
			port:     26,
			match:    false,
		},
		{
			title:    "single set match",
			ranges:   nil,
			ipSetIds: []string{"set26"},
			ip:       "192.168.4.5",
			port:     26,
			match:    true,
		},
		{
			title:    "single set no match",
			ranges:   nil,
			ipSetIds: []string{"set12"},
			ip:       "192.168.4.5",
			port:     26,
			match:    false,
		},
		{
			title:    "multi set match",
			ranges:   nil,
			ipSetIds: []string{"set12", "set26"},
			ip:       "192.168.4.5",
			port:     26,
			match:    true,
		},
		{
			title:    "set no match, range match",
			ranges:   []*proto.PortRange{{First: 26, Last: 26}},
			ipSetIds: []string{"set12"},
			ip:       "192.168.4.5",
			port:     26,
			match:    true,
		},
		{
			title:    "set match, range no match",
			ranges:   []*proto.PortRange{{First: 26, Last: 26}},
			ipSetIds: []string{"set12"},
			ip:       "192.168.4.5",
			port:     12,
			match:    true,
		},
		{
			title:    "set no match, range no match",
			ranges:   []*proto.PortRange{{First: 26, Last: 26}},
			ipSetIds: []string{"set12"},
			ip:       "192.168.4.5",
			port:     112,
			match:    false,
		},
	}
	store := policystore.NewPolicyStore()
	set12 := policystore.NewIPSet(proto.IPSetUpdate_PORTS)
	set12.AddString("12")
	set26 := policystore.NewIPSet(proto.IPSetUpdate_PORTS)
	set26.AddString("26")
	store.IPSetByID["set12"] = set12
	store.IPSetByID["set26"] = set26
	r := &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Source: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/sam",
		},
		Destination: &auth.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/testns/sa/ian",
		},
	}}
	flow := NewCheckRequestToFlowAdapter(r)

	req := NewRequestCache(store, flow)
	for i, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)

			Expect(matchPort("test", tc.ranges, tc.ipSetIds, req.getIPSet, tc.port)).To(Equal(tc.match), "Test case: %d", i)
		})
	}
}*/

func TestMatchNet(t *testing.T) {
	testCases := []struct {
		title string
		nets  []string
		ip    string
		match bool
	}{
		{
			title: "empty",
			nets:  nil,
			ip:    "45ab:0023::abcd",
			match: true,
		},
		{
			title: "single v4 net match",
			nets:  []string{"192.168.3.0/24"},
			ip:    "192.168.3.145",
			match: true,
		},
		{
			title: "single v6 net match",
			nets:  []string{"45ab:0023::/32"},
			ip:    "45ab:0023::abcd",
			match: true,
		},
		{
			title: "v4 ip v6 net no match",
			nets:  []string{"55ae:4481::/0"},
			ip:    "192.168.3.145",
			match: false,
		},
		{
			title: "v6 ip v4 set no match",
			nets:  []string{"10.0.0.0/0"},
			ip:    "45ab:0023::abcd",
			match: false,
		},
		{
			title: "mixed v6 net match",
			nets:  []string{"45ab:0023::/32", "192.168.0.0/16"},
			ip:    "45ab:0023::abcd",
			match: true,
		},
		{
			title: "mixed v4 net match",
			nets:  []string{"45ab:0023::/32", "192.168.0.0/16"},
			ip:    "192.168.21.21",
			match: true,
		},
		{
			title: "single v4 net no match",
			nets:  []string{"192.168.0.0/16"},
			ip:    "55.39.128.9",
			match: false,
		},
		{
			title: "single v6 net no match",
			nets:  []string{"45ab:0023::/32"},
			ip:    "85ab:0023::abcd",
			match: false,
		},
		{
			title: "multiple nets no match",
			nets:  []string{"45.81.99.128/25", "10.0.0.0/8", "13.12.0.0/16"},
			ip:    "45.81.99.1",
			match: false,
		},
		{
			title: "multiple nets match",
			nets:  []string{"45.81.99.0/24", "10.0.0.0/8", "13.12.0.0/16"},
			ip:    "45.81.99.1",
			match: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			RegisterTestingT(t)

			ip := libnet.ParseIP(tc.ip)
			Expect(matchNet("test", tc.nets, ip.Network().IP)).To(Equal(tc.match))
		})
	}
}

func TestMatchNetBadCIDR(t *testing.T) {
	RegisterTestingT(t)

	ip := libnet.ParseIP("192.168.5.6")
	nets := []string{"192.168.0.0.0/16"}
	Expect(matchNet("test", nets, ip.Network().IP)).To(BeFalse())
}

/*func TestMatchNets(t *testing.T) {
	RegisterTestingT(t)

	testCases := []struct {
		title     string
		nets      []string
		srcIP     string
		dstIP     string
		srcResult bool
		dstResult bool
	}{
		{"empty nets", nil, "192.168.1.1", "192.168.1.1", true, true},
		{"single net match", []string{"192.168.1.0/24"}, "192.168.1.1", "192.168.1.1", true, true},
		{"single net no match", []string{"192.168.2.0/24"}, "192.168.1.1", "192.168.1.1", false, false},
		{"multiple nets match", []string{"192.168.2.0/24", "192.168.1.0/24"}, "192.168.1.1", "192.168.1.1", true, true},
		{"multiple nets no match", []string{"192.168.2.0/24", "192.168.3.0/24"}, "192.168.1.1", "192.168.1.1", false, false},
		{"invalid net", []string{"invalid"}, "192.168.1.1", "192.168.1.1", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			srcIP := libnet.ParseIP(tc.srcIP).IP
			dstIP := libnet.ParseIP(tc.dstIP).IP

			srcFlow := &mocks.Flow{}
			srcFlow.On("GetSourceIP").Return(srcIP)

			dstFlow := &mocks.Flow{}
			dstFlow.On("GetDestIP").Return(dstIP)

			srcResult := matchSrcNet(&proto.Rule{SrcNet: tc.nets}, &requestCache{srcFlow, nil})
			dstResult := matchDstNet(&proto.Rule{DstNet: tc.nets}, &requestCache{dstFlow, nil})

			Expect(srcResult).To(Equal(tc.srcResult), "Test case: %s", tc.title)
			Expect(dstResult).To(Equal(tc.dstResult), "Test case: %s", tc.title)
		})
	}
}

func TestMatchPorts(t *testing.T) {
	RegisterTestingT(t)

	testCases := []struct {
		title              string
		srcRanges          []*proto.PortRange
		dstRanges          []*proto.PortRange
		notSrcRanges       []*proto.PortRange
		notDstRanges       []*proto.PortRange
		srcNamedPortIds    []string
		dstNamedPortIds    []string
		notSrcNamedPortIds []string
		notDstNamedPortIds []string
		srcPort            int
		dstPort            int
		match              bool
	}{
		{
			title:              "empty match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            80,
			match:              true,
		},
		{
			title:              "single numeric src port match",
			srcRanges:          []*proto.PortRange{{First: 12, Last: 12}},
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            80,
			match:              true,
		},
		{
			title:              "single numeric dst port match",
			srcRanges:          nil,
			dstRanges:          []*proto.PortRange{{First: 80, Last: 80}},
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            80,
			match:              true,
		},
		{
			title:              "single numeric src port no match",
			srcRanges:          []*proto.PortRange{{First: 12, Last: 12}},
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            11,
			dstPort:            80,
			match:              false,
		},
		{
			title:              "single numeric dst port no match",
			srcRanges:          nil,
			dstRanges:          []*proto.PortRange{{First: 80, Last: 80}},
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            81,
			match:              false,
		},
		{
			title:              "range src port match",
			srcRanges:          []*proto.PortRange{{First: 10, Last: 20}},
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            15,
			dstPort:            80,
			match:              true,
		},
		{
			title:              "range dst port match",
			srcRanges:          nil,
			dstRanges:          []*proto.PortRange{{First: 70, Last: 90}},
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            80,
			match:              true,
		},
		{
			title:              "range src port no match",
			srcRanges:          []*proto.PortRange{{First: 10, Last: 20}},
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            21,
			dstPort:            80,
			match:              false,
		},
		{
			title:              "range dst port no match",
			srcRanges:          nil,
			dstRanges:          []*proto.PortRange{{First: 70, Last: 90}},
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            91,
			match:              false,
		},
		{
			title:              "single set src port match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    []string{"set12"},
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            80,
			match:              true,
		},
		{
			title:              "single set dst port match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    []string{"set80"},
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            80,
			match:              true,
		},
		{
			title:              "single set src port no match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    []string{"set12"},
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            13,
			dstPort:            80,
			match:              false,
		},
		{
			title:              "single set dst port no match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    []string{"set80"},
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            81,
			match:              false,
		},
		{
			title:              "multi set src port match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    []string{"set12", "set15"},
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            15,
			dstPort:            80,
			match:              true,
		},
		{
			title:              "multi set dst port match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    []string{"set80", "set85"},
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            85,
			match:              true,
		},
		{
			title:              "set no match, range src port match",
			srcRanges:          []*proto.PortRange{{First: 15, Last: 15}},
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    []string{"set12"},
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            15,
			dstPort:            80,
			match:              true,
		},
		{
			title:              "set no match, range dst port match",
			srcRanges:          nil,
			dstRanges:          []*proto.PortRange{{First: 85, Last: 85}},
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    []string{"set80"},
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            85,
			match:              true,
		},
		{
			title:              "set match, range src port no match",
			srcRanges:          []*proto.PortRange{{First: 15, Last: 15}},
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    []string{"set12"},
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            80,
			match:              true,
		},
		{
			title:              "set match, range dst port no match",
			srcRanges:          nil,
			dstRanges:          []*proto.PortRange{{First: 85, Last: 85}},
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    []string{"set80"},
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            80,
			match:              true,
		},
		{
			title:              "set no match, range src port no match",
			srcRanges:          []*proto.PortRange{{First: 15, Last: 15}},
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    []string{"set12"},
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            16,
			dstPort:            80,
			match:              false,
		},
		{
			title:              "set no match, range dst port no match",
			srcRanges:          nil,
			dstRanges:          []*proto.PortRange{{First: 85, Last: 85}},
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    []string{"set80"},
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            86,
			match:              false,
		},
		{
			title:              "not src port match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       []*proto.PortRange{{First: 15, Last: 15}},
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            16,
			dstPort:            80,
			match:              true,
		},
		{
			title:              "not dst port match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       []*proto.PortRange{{First: 85, Last: 85}},
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            86,
			match:              true,
		},
		{
			title:              "not src port no match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       []*proto.PortRange{{First: 15, Last: 15}},
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            15,
			dstPort:            80,
			match:              false,
		},
		{
			title:              "not dst port no match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       []*proto.PortRange{{First: 85, Last: 85}},
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: nil,
			srcPort:            12,
			dstPort:            85,
			match:              false,
		},
		{
			title:              "not src named port match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: []string{"set15"},
			notDstNamedPortIds: nil,
			srcPort:            16,
			dstPort:            80,
			match:              true,
		},
		{
			title:              "not dst named port match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: []string{"set85"},
			srcPort:            12,
			dstPort:            86,
			match:              true,
		},
		{
			title:              "not src named port no match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: []string{"set15"},
			notDstNamedPortIds: nil,
			srcPort:            15,
			dstPort:            80,
			match:              false,
		},
		{
			title:              "not dst named port no match",
			srcRanges:          nil,
			dstRanges:          nil,
			notSrcRanges:       nil,
			notDstRanges:       nil,
			srcNamedPortIds:    nil,
			dstNamedPortIds:    nil,
			notSrcNamedPortIds: nil,
			notDstNamedPortIds: []string{"set85"},
			srcPort:            12,
			dstPort:            85,
			match:              false,
		},
	}

	store := policystore.NewPolicyStore()
	set12 := policystore.NewIPSet(proto.IPSetUpdate_PORTS)
	set12.AddString("12")
	set15 := policystore.NewIPSet(proto.IPSetUpdate_PORTS)
	set15.AddString("15")
	set80 := policystore.NewIPSet(proto.IPSetUpdate_PORTS)
	set80.AddString("80")
	set85 := policystore.NewIPSet(proto.IPSetUpdate_PORTS)
	set85.AddString("85")
	store.IPSetByID["set12"] = set12
	store.IPSetByID["set15"] = set15
	store.IPSetByID["set80"] = set80
	store.IPSetByID["set85"] = set85

	for i, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			fl := &mocks.Flow{}
			fl.On("GetSourcePort").Return(tc.srcPort)
			fl.On("GetDestPort").Return(tc.dstPort)

			srcMatch := matchSrcPort(&proto.Rule{SrcPorts: tc.srcRanges, SrcNamedPortIpSetIds: tc.srcNamedPortIds, NotSrcPorts: tc.notSrcRanges, NotSrcNamedPortIpSetIds: tc.notSrcNamedPortIds}, &requestCache{fl, store})
			dstMatch := matchDstPort(&proto.Rule{DstPorts: tc.dstRanges, DstNamedPortIpSetIds: tc.dstNamedPortIds, NotDstPorts: tc.notDstRanges, NotDstNamedPortIpSetIds: tc.notDstNamedPortIds}, &requestCache{fl, store})
			Expect(srcMatch && dstMatch).To(Equal(tc.match), "Test case: %d", i)
		})
	}
}*/

func TestMatchDstIPPortSetIds(t *testing.T) {
	RegisterTestingT(t)

	testCases := []struct {
		title    string
		rule     *proto.Rule
		destIP   string
		destPort int
		proto    int
		expected bool
	}{
		{
			title: "match IP in set80",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"set80"},
			},
			destIP:   "192.168.1.1",
			destPort: 80,
			proto:    6,
			expected: true,
		},
		{
			title: "no match IP in set80",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"set80"},
			},
			destIP:   "192.168.1.3",
			destPort: 80,
			proto:    6,
			expected: false,
		},
		{
			title: "match IP in set443",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"set443"},
			},
			destIP:   "192.168.1.2",
			destPort: 443,
			proto:    17,
			expected: true,
		},
		{
			title: "no match IP in set443",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"set443"},
			},
			destIP:   "192.168.1.4",
			destPort: 443,
			proto:    17,
			expected: false,
		},
		{
			title: "match IP in set with multiple entries",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"setMulti"},
			},
			destIP:   "192.168.1.5",
			destPort: 8080,
			proto:    6,
			expected: true,
		},
		{
			title: "no match IP in set with multiple entries",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"setMulti"},
			},
			destIP:   "192.168.1.6",
			destPort: 8080,
			proto:    6,
			expected: false,
		},
		{
			title: "match IP in set with different protocol",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"setProto"},
			},
			destIP:   "192.168.1.7",
			destPort: 53,
			proto:    17,
			expected: true,
		},
		{
			title: "no match IP in set with different protocol",
			rule: &proto.Rule{
				DstIpPortSetIds: []string{"setProto"},
			},
			destIP:   "192.168.1.7",
			destPort: 53,
			proto:    6,
			expected: false,
		},
	}

	store := policystore.NewPolicyStore()
	set80 := policystore.NewIPSet(proto.IPSetUpdate_IP)
	set80.AddString("192.168.1.1,tcp:80")
	set443 := policystore.NewIPSet(proto.IPSetUpdate_IP)
	set443.AddString("192.168.1.2,udp:443")
	setMulti := policystore.NewIPSet(proto.IPSetUpdate_IP)
	setMulti.AddString("192.168.1.5,tcp:8080")
	setMulti.AddString("192.168.1.5,tcp:9090")
	setProto := policystore.NewIPSet(proto.IPSetUpdate_IP)
	setProto.AddString("192.168.1.7,udp:53")
	store.IPSetByID["set80"] = set80
	store.IPSetByID["set443"] = set443
	store.IPSetByID["setMulti"] = setMulti
	store.IPSetByID["setProto"] = setProto

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			fl := &mocks.Flow{}
			fl.On("GetDestIP").Return(libnet.ParseIP(tc.destIP).IP)
			fl.On("GetDestPort").Return(tc.destPort)
			fl.On("GetProtocol").Return(tc.proto)

			req := &requestCache{fl, store}
			Expect(matchDstIPPortSetIds(tc.rule, req)).To(Equal(tc.expected), "Test case: %s", tc.title)
		})
	}
}
