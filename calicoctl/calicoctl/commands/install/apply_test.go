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

package install

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// testMapper wraps a DefaultRESTMapper to satisfy meta.ResettableRESTMapper for
// tests (Reset is a no-op since the test mappings are static).
type testMapper struct {
	*meta.DefaultRESTMapper
}

func (testMapper) Reset() {}

func newTestMapper() testMapper {
	m := meta.NewDefaultRESTMapper(nil)
	// A namespaced core kind and a cluster-scoped kind.
	m.Add(schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}, meta.RESTScopeNamespace)
	m.Add(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}, meta.RESTScopeRoot)
	m.Add(schema.GroupVersionKind{Group: "operator.tigera.io", Version: "v1", Kind: "Installation"}, meta.RESTScopeRoot)
	return testMapper{m}
}

func TestDecodeManifest(t *testing.T) {
	manifest := []byte(`
apiVersion: v1
kind: Namespace
metadata:
  name: tigera-operator
---
# a comment-only block should be skipped
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tigera-operator
  namespace: tigera-operator
`)
	objs, err := decodeManifest(manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(objs) != 2 {
		t.Fatalf("expected 2 objects, got %d", len(objs))
	}
	if objs[0].GetKind() != "Namespace" || objs[1].GetKind() != "Deployment" {
		t.Errorf("unexpected kinds: %q, %q", objs[0].GetKind(), objs[1].GetKind())
	}
}

func TestSortObjects(t *testing.T) {
	mk := func(group, kind, name string) unstructured.Unstructured {
		o := unstructured.Unstructured{}
		o.SetGroupVersionKind(schema.GroupVersionKind{Group: group, Version: "v1", Kind: kind})
		o.SetName(name)
		return o
	}
	// Intentionally out of order.
	objs := []unstructured.Unstructured{
		mk("operator.tigera.io", "Installation", "default"),
		mk("apps", "Deployment", "tigera-operator"),
		mk("", "Namespace", "tigera-operator"),
		mk("apiextensions.k8s.io", "CustomResourceDefinition", "installations.operator.tigera.io"),
		mk("rbac.authorization.k8s.io", "ClusterRole", "tigera-operator"),
	}
	sortObjects(objs)

	gotOrder := make([]string, len(objs))
	for i := range objs {
		gotOrder[i] = objs[i].GetKind()
	}
	want := []string{"CustomResourceDefinition", "Namespace", "ClusterRole", "Deployment", "Installation"}
	for i := range want {
		if gotOrder[i] != want[i] {
			t.Fatalf("apply order = %v, want %v", gotOrder, want)
		}
	}
}

func TestSortObjectsReverse(t *testing.T) {
	mk := func(group, kind string) unstructured.Unstructured {
		o := unstructured.Unstructured{}
		o.SetGroupVersionKind(schema.GroupVersionKind{Group: group, Version: "v1", Kind: kind})
		return o
	}
	objs := []unstructured.Unstructured{
		mk("apiextensions.k8s.io", "CustomResourceDefinition"),
		mk("", "Namespace"),
		mk("operator.tigera.io", "Installation"),
		mk("apps", "Deployment"),
	}
	sortObjectsReverse(objs)
	got := []string{objs[0].GetKind(), objs[1].GetKind(), objs[2].GetKind(), objs[3].GetKind()}
	want := []string{"Installation", "Deployment", "Namespace", "CustomResourceDefinition"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delete order = %v, want %v", got, want)
		}
	}
}

func TestDeleteObject_IgnoresMissing(t *testing.T) {
	// An empty fake client has no objects, so delete should report skipped, not error.
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	a := &applier{mapper: newTestMapper(), dyn: dyn}

	ns := unstructured.Unstructured{}
	ns.SetGroupVersionKind(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"})
	ns.SetName("tigera-operator")

	res, err := a.deleteObject(context.Background(), &ns)
	if err != nil {
		t.Fatalf("delete of missing object errored: %v", err)
	}
	if !res.skipped {
		t.Error("expected delete of missing object to be reported as skipped")
	}
}

func TestResourceFor_Scope(t *testing.T) {
	a := &applier{mapper: newTestMapper(), dyn: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())}

	// Namespaced object: missing namespace should default.
	dep := unstructured.Unstructured{}
	dep.SetGroupVersionKind(schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"})
	dep.SetName("x")
	if _, err := a.resourceFor(&dep); err != nil {
		t.Errorf("namespaced resourceFor failed: %v", err)
	}

	// Cluster-scoped object resolves without a namespace.
	ns := unstructured.Unstructured{}
	ns.SetGroupVersionKind(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"})
	ns.SetName("tigera-operator")
	if _, err := a.resourceFor(&ns); err != nil {
		t.Errorf("cluster-scoped resourceFor failed: %v", err)
	}

	// Unknown kind should error (no REST mapping).
	unknown := unstructured.Unstructured{}
	unknown.SetGroupVersionKind(schema.GroupVersionKind{Group: "x", Version: "v1", Kind: "Nope"})
	unknown.SetName("n")
	if _, err := a.resourceFor(&unknown); err == nil {
		t.Error("expected error for unknown kind, got nil")
	}
}

func TestApplyObject_UsesServerSideApply(t *testing.T) {
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())

	// The fake dynamic client does not implement server-side-apply create
	// semantics, so intercept the patch to assert the request is shaped
	// correctly (apply patch type, resolved resource) and return the object.
	var gotPatchType types.PatchType
	var gotResource string
	dyn.PrependReactor("patch", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		pa := action.(k8stesting.PatchAction)
		gotPatchType = pa.GetPatchType()
		gotResource = pa.GetResource().Resource
		ret := &unstructured.Unstructured{}
		ret.SetName(pa.GetName())
		return true, ret, nil
	})

	a := &applier{mapper: newTestMapper(), dyn: dyn}
	ns := unstructured.Unstructured{}
	ns.SetGroupVersionKind(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"})
	ns.SetName("tigera-operator")

	if _, err := a.applyObject(context.Background(), &ns); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if gotPatchType != types.ApplyPatchType {
		t.Errorf("patch type = %q, want %q", gotPatchType, types.ApplyPatchType)
	}
	if gotResource != "namespaces" {
		t.Errorf("resource = %q, want namespaces", gotResource)
	}
}

func TestCRDEstablished(t *testing.T) {
	mk := func(condType, status string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"status": map[string]any{
				"conditions": []any{
					map[string]any{"type": condType, "status": status},
				},
			},
		}}
	}
	if !crdEstablished(mk("Established", "True")) {
		t.Error("expected Established=True to report true")
	}
	if crdEstablished(mk("Established", "False")) {
		t.Error("expected Established=False to report false")
	}
	if crdEstablished(mk("NamesAccepted", "True")) {
		t.Error("expected non-Established condition to report false")
	}
	if crdEstablished(&unstructured.Unstructured{Object: map[string]any{}}) {
		t.Error("expected missing status to report false")
	}
}

// TestEmbeddedWaves sanity-checks the embedded operator manifests so a bad
// regeneration (wrong file, empty file) is caught at build/test time.
func TestEmbeddedWaves(t *testing.T) {
	waves := installWaves()
	if len(waves) != 3 {
		t.Fatalf("expected 3 install waves, got %d", len(waves))
	}

	// Wave 1: every object is a CRD, and the Installation CRD is present.
	crds, err := decodeManifest(waves[0].yaml)
	if err != nil {
		t.Fatalf("failed to decode CRD wave: %v", err)
	}
	if len(crds) == 0 {
		t.Fatal("CRD wave decoded to zero objects")
	}
	foundInstallationCRD := false
	for i := range crds {
		if crds[i].GetKind() != "CustomResourceDefinition" {
			t.Errorf("CRD wave contains non-CRD kind %q", crds[i].GetKind())
		}
		if crds[i].GetName() == installationCRDName {
			foundInstallationCRD = true
		}
	}
	if !foundInstallationCRD {
		t.Errorf("CRD wave does not contain %q", installationCRDName)
	}

	// Wave 2: operator deployment + namespace present.
	dep, err := decodeManifest(waves[1].yaml)
	if err != nil {
		t.Fatalf("failed to decode operator wave: %v", err)
	}
	kinds := map[string]bool{}
	for i := range dep {
		kinds[dep[i].GetKind()] = true
	}
	for _, want := range []string{"Namespace", "Deployment", "ServiceAccount"} {
		if !kinds[want] {
			t.Errorf("operator wave missing kind %q", want)
		}
	}

	// Wave 3: all objects are operator.tigera.io custom resources.
	crs, err := decodeManifest(waves[2].yaml)
	if err != nil {
		t.Fatalf("failed to decode custom-resources wave: %v", err)
	}
	if len(crs) == 0 {
		t.Fatal("custom-resources wave decoded to zero objects")
	}
	for i := range crs {
		if crs[i].GroupVersionKind().Group != operatorConfigGroup {
			t.Errorf("custom-resources wave contains non-operator group %q", crs[i].GroupVersionKind().Group)
		}
	}
}
