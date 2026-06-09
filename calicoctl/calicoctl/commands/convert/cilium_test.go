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
	"strings"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

// asNetworkPolicy converts a single document and asserts it produced exactly one
// NetworkPolicy.
func asNetworkPolicy(t *testing.T, doc string) *apiv3.NetworkPolicy {
	t.Helper()
	objs, err := FromCiliumYAML([]byte(doc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(objs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(objs))
	}
	np, ok := objs[0].(*apiv3.NetworkPolicy)
	if !ok {
		t.Fatalf("expected *NetworkPolicy, got %T", objs[0])
	}
	return np
}

func TestConvert_KindAndNamespaceMapping(t *testing.T) {
	t.Run("CNP without namespace defaults to default namespace", func(t *testing.T) {
		np := asNetworkPolicy(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-app
spec:
  endpointSelector:
    matchLabels:
      app: web
`)
		if np.Namespace != "default" {
			t.Errorf("namespace = %q, want default", np.Namespace)
		}
		if np.Name != "allow-app" {
			t.Errorf("name = %q, want allow-app", np.Name)
		}
		if np.Spec.Selector != "app == 'web'" {
			t.Errorf("selector = %q", np.Spec.Selector)
		}
	})

	t.Run("CNP honours explicit namespace", func(t *testing.T) {
		np := asNetworkPolicy(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: p
  namespace: prod
spec:
  endpointSelector: {}
`)
		if np.Namespace != "prod" {
			t.Errorf("namespace = %q, want prod", np.Namespace)
		}
		// Empty endpointSelector means all endpoints in scope.
		if np.Spec.Selector != "all()" {
			t.Errorf("selector = %q, want all()", np.Spec.Selector)
		}
	})

	t.Run("CCNP maps to GlobalNetworkPolicy", func(t *testing.T) {
		objs, err := FromCiliumYAML([]byte(`
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: global-p
spec:
  endpointSelector:
    matchLabels:
      app: web
`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		gnp, ok := objs[0].(*apiv3.GlobalNetworkPolicy)
		if !ok {
			t.Fatalf("expected *GlobalNetworkPolicy, got %T", objs[0])
		}
		if gnp.Name != "global-p" {
			t.Errorf("name = %q", gnp.Name)
		}
	})

	t.Run("specs produce one indexed policy each", func(t *testing.T) {
		objs, err := FromCiliumYAML([]byte(`
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: multi
  namespace: ns
specs:
  - endpointSelector: {}
  - endpointSelector: {}
`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(objs) != 2 {
			t.Fatalf("expected 2 resources, got %d", len(objs))
		}
		got := []string{objs[0].(*apiv3.NetworkPolicy).Name, objs[1].(*apiv3.NetworkPolicy).Name}
		if got[0] != "multi-0" || got[1] != "multi-1" {
			t.Errorf("names = %v, want [multi-0 multi-1]", got)
		}
	})
}

func TestConvert_IngressL3L4(t *testing.T) {
	np := asNetworkPolicy(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: p
  namespace: ns
spec:
  endpointSelector:
    matchLabels:
      app: web
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: client
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
`)
	if len(np.Spec.Types) != 1 || np.Spec.Types[0] != apiv3.PolicyTypeIngress {
		t.Fatalf("types = %v, want [Ingress]", np.Spec.Types)
	}
	if len(np.Spec.Ingress) != 1 {
		t.Fatalf("expected 1 ingress rule, got %d", len(np.Spec.Ingress))
	}
	r := np.Spec.Ingress[0]
	if r.Action != apiv3.Allow {
		t.Errorf("action = %q, want Allow", r.Action)
	}
	if r.Source.Selector != "app == 'client'" {
		t.Errorf("source selector = %q", r.Source.Selector)
	}
	if r.Protocol == nil || r.Protocol.String() != "TCP" {
		t.Errorf("protocol = %v, want TCP", r.Protocol)
	}
	if len(r.Destination.Ports) != 1 || r.Destination.Ports[0].String() != "80" {
		t.Errorf("dest ports = %v, want [80]", r.Destination.Ports)
	}
}

func TestConvert_EgressCIDRAndPortRange(t *testing.T) {
	np := asNetworkPolicy(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: p
  namespace: ns
spec:
  endpointSelector: {}
  egress:
    - toCIDR:
        - 10.0.0.0/8
      toPorts:
        - ports:
            - port: "8080"
              endPort: 8090
              protocol: UDP
`)
	if len(np.Spec.Egress) != 1 {
		t.Fatalf("expected 1 egress rule, got %d", len(np.Spec.Egress))
	}
	r := np.Spec.Egress[0]
	if len(r.Destination.Nets) != 1 || r.Destination.Nets[0] != "10.0.0.0/8" {
		t.Errorf("dest nets = %v", r.Destination.Nets)
	}
	if r.Protocol == nil || r.Protocol.String() != "UDP" {
		t.Errorf("protocol = %v, want UDP", r.Protocol)
	}
	if len(r.Destination.Ports) != 1 || r.Destination.Ports[0].String() != "8080:8090" {
		t.Errorf("dest ports = %v, want [8080:8090]", r.Destination.Ports)
	}
}

func TestConvert_CIDRSetWithExcept(t *testing.T) {
	np := asNetworkPolicy(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: p
  namespace: ns
spec:
  endpointSelector: {}
  ingress:
    - fromCIDRSet:
        - cidr: 10.0.0.0/8
          except:
            - 10.1.0.0/16
`)
	r := np.Spec.Ingress[0]
	if len(r.Source.Nets) != 1 || r.Source.Nets[0] != "10.0.0.0/8" {
		t.Errorf("nets = %v", r.Source.Nets)
	}
	if len(r.Source.NotNets) != 1 || r.Source.NotNets[0] != "10.1.0.0/16" {
		t.Errorf("notNets = %v", r.Source.NotNets)
	}
}

func TestConvert_WorldEntity(t *testing.T) {
	np := asNetworkPolicy(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: p
  namespace: ns
spec:
  endpointSelector: {}
  egress:
    - toEntities:
        - world
`)
	// "world" splits into one rule per IP family (Calico forbids mixing them).
	if len(np.Spec.Egress) != 2 {
		t.Fatalf("expected 2 egress rules, got %d", len(np.Spec.Egress))
	}
	got := []string{
		strings.Join(np.Spec.Egress[0].Destination.Nets, ","),
		strings.Join(np.Spec.Egress[1].Destination.Nets, ","),
	}
	if got[0] != "0.0.0.0/0" || got[1] != "::/0" {
		t.Errorf("nets = %v, want [0.0.0.0/0 ::/0]", got)
	}
}

func TestConvert_IngressDenyIsDenyAction(t *testing.T) {
	np := asNetworkPolicy(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: p
  namespace: ns
spec:
  endpointSelector: {}
  ingressDeny:
    - fromCIDR:
        - 192.168.0.0/16
`)
	r := np.Spec.Ingress[0]
	if r.Action != apiv3.Deny {
		t.Errorf("action = %q, want Deny", r.Action)
	}
}

func TestConvert_NamespaceLabelBecomesNamespaceSelector(t *testing.T) {
	np := asNetworkPolicy(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: p
  namespace: ns
spec:
  endpointSelector: {}
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: client
            k8s:io.kubernetes.pod.namespace: other
`)
	r := np.Spec.Ingress[0]
	if r.Source.Selector != "app == 'client'" {
		t.Errorf("selector = %q", r.Source.Selector)
	}
	want := "kubernetes.io/metadata.name == 'other'"
	if r.Source.NamespaceSelector != want {
		t.Errorf("namespaceSelector = %q, want %q", r.Source.NamespaceSelector, want)
	}
}

func TestConvert_ANYProtocolExpandsToTCPAndUDP(t *testing.T) {
	np := asNetworkPolicy(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: p
  namespace: ns
spec:
  endpointSelector: {}
  ingress:
    - toPorts:
        - ports:
            - port: "53"
              protocol: ANY
`)
	if len(np.Spec.Ingress) != 2 {
		t.Fatalf("expected 2 rules (TCP+UDP), got %d", len(np.Spec.Ingress))
	}
	gotProtos := []string{np.Spec.Ingress[0].Protocol.String(), np.Spec.Ingress[1].Protocol.String()}
	if gotProtos[0] != "TCP" || gotProtos[1] != "UDP" {
		t.Errorf("protocols = %v, want [TCP UDP]", gotProtos)
	}
}

func TestConvert_HTTPL7(t *testing.T) {
	np := asNetworkPolicy(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: p
  namespace: ns
spec:
  endpointSelector: {}
  ingress:
    - toPorts:
        - ports:
            - port: "80"
              protocol: TCP
          rules:
            http:
              - method: GET
                path: /foo
              - method: POST
                path: "/bar/.*"
`)
	r := np.Spec.Ingress[0]
	if r.HTTP == nil {
		t.Fatal("expected HTTP match")
	}
	if strings.Join(r.HTTP.Methods, ",") != "GET,POST" {
		t.Errorf("methods = %v", r.HTTP.Methods)
	}
	if len(r.HTTP.Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(r.HTTP.Paths))
	}
	if r.HTTP.Paths[0].Exact != "/foo" {
		t.Errorf("path[0] = %+v, want exact /foo", r.HTTP.Paths[0])
	}
	if r.HTTP.Paths[1].Prefix != "/bar/" {
		t.Errorf("path[1] = %+v, want prefix /bar/", r.HTTP.Paths[1])
	}
	// HTTP forces protocol TCP only.
	if r.Protocol == nil || r.Protocol.String() != "TCP" {
		t.Errorf("protocol = %v, want TCP", r.Protocol)
	}
}

func TestConvert_ICMP(t *testing.T) {
	np := asNetworkPolicy(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: p
  namespace: ns
spec:
  endpointSelector: {}
  ingress:
    - icmps:
        - fields:
            - type: "8"
              family: IPv4
`)
	r := np.Spec.Ingress[0]
	if r.Protocol == nil || r.Protocol.String() != "ICMP" {
		t.Errorf("protocol = %v, want ICMP", r.Protocol)
	}
	if r.ICMP == nil || r.ICMP.Type == nil || *r.ICMP.Type != 8 {
		t.Errorf("icmp = %+v, want type 8", r.ICMP)
	}
}

func TestConvert_MatchExpressions(t *testing.T) {
	np := asNetworkPolicy(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: p
  namespace: ns
spec:
  endpointSelector:
    matchLabels:
      app: web
    matchExpressions:
      - key: tier
        operator: In
        values: [frontend, backend]
      - key: legacy
        operator: DoesNotExist
`)
	want := "app == 'web' && tier in { 'frontend', 'backend' } && ! has(legacy)"
	if np.Spec.Selector != want {
		t.Errorf("selector = %q\nwant      %q", np.Spec.Selector, want)
	}
}

// TestConvert_UnsupportedFails covers the fail-closed behaviour: every
// unsupported construct must produce an error mentioning the offending field.
func TestConvert_UnsupportedFails(t *testing.T) {
	cases := []struct {
		name      string
		doc       string
		errSubstr string
	}{
		{
			name:      "toFQDNs",
			errSubstr: "toFQDNs",
			doc: `
kind: CiliumNetworkPolicy
metadata: {name: p, namespace: ns}
spec:
  endpointSelector: {}
  egress:
    - toFQDNs:
        - matchName: example.com
`,
		},
		{
			name:      "toServices",
			errSubstr: "toServices",
			doc: `
kind: CiliumNetworkPolicy
metadata: {name: p, namespace: ns}
spec:
  endpointSelector: {}
  egress:
    - toServices:
        - k8sService: {serviceName: foo, namespace: ns}
`,
		},
		{
			name:      "fromRequires",
			errSubstr: "fromRequires",
			doc: `
kind: CiliumNetworkPolicy
metadata: {name: p, namespace: ns}
spec:
  endpointSelector: {}
  ingress:
    - fromRequires:
        - matchLabels: {team: a}
`,
		},
		{
			name:      "nodeSelector",
			errSubstr: "nodeSelector",
			doc: `
kind: CiliumClusterwideNetworkPolicy
metadata: {name: p}
spec:
  nodeSelector:
    matchLabels: {role: worker}
`,
		},
		{
			name:      "host entity",
			errSubstr: "entity",
			doc: `
kind: CiliumNetworkPolicy
metadata: {name: p, namespace: ns}
spec:
  endpointSelector: {}
  ingress:
    - fromEntities: [host]
`,
		},
		{
			name:      "kafka L7",
			errSubstr: "Kafka",
			doc: `
kind: CiliumNetworkPolicy
metadata: {name: p, namespace: ns}
spec:
  endpointSelector: {}
  ingress:
    - toPorts:
        - ports: [{port: "9092", protocol: TCP}]
          rules:
            kafka:
              - role: produce
`,
		},
		{
			name:      "http header match",
			errSubstr: "header",
			doc: `
kind: CiliumNetworkPolicy
metadata: {name: p, namespace: ns}
spec:
  endpointSelector: {}
  ingress:
    - toPorts:
        - ports: [{port: "80", protocol: TCP}]
          rules:
            http:
              - method: GET
                headers: ["X-Token: secret"]
`,
		},
		{
			name:      "regex http path",
			errSubstr: "regular expression",
			doc: `
kind: CiliumNetworkPolicy
metadata: {name: p, namespace: ns}
spec:
  endpointSelector: {}
  ingress:
    - toPorts:
        - ports: [{port: "80", protocol: TCP}]
          rules:
            http:
              - path: "/foo[0-9]+"
`,
		},
		{
			name:      "reserved label in selector",
			errSubstr: "reserved",
			doc: `
kind: CiliumNetworkPolicy
metadata: {name: p, namespace: ns}
spec:
  endpointSelector:
    matchLabels:
      reserved:health: ""
`,
		},
		{
			name:      "enableDefaultDeny false",
			errSubstr: "enableDefaultDeny",
			doc: `
kind: CiliumNetworkPolicy
metadata: {name: p, namespace: ns}
spec:
  endpointSelector: {}
  enableDefaultDeny:
    ingress: false
`,
		},
		{
			name:      "unknown field (strict)",
			errSubstr: "madeUpField",
			doc: `
kind: CiliumNetworkPolicy
metadata: {name: p, namespace: ns}
spec:
  endpointSelector: {}
  madeUpField: true
`,
		},
		{
			name:      "unknown kind",
			errSubstr: "unsupported kind",
			doc: `
kind: NetworkPolicy
metadata: {name: p}
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromCiliumYAML([]byte(tc.doc))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errSubstr)
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.errSubstr)
			}
		})
	}
}
