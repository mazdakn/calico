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
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"

	yamlsep "github.com/projectcalico/calico/calicoctl/calicoctl/util/yaml"
)

// fieldManager identifies calicoctl as the owner of the fields it applies, for
// server-side apply conflict tracking.
const fieldManager = "calicoctl-install"

// installationCRDName is the CustomResourceDefinition that the operator-config
// custom resources depend on; we wait for it to be Established after applying the
// CRD wave.
const installationCRDName = "installations.operator.tigera.io"

// applier server-side-applies arbitrary Kubernetes manifests using a dynamic
// client and a discovery-backed RESTMapper, so calicoctl can create core objects
// (CRDs, Namespace, RBAC, Deployment) and operator custom resources that its
// typed Calico client cannot.
type applier struct {
	dyn    dynamic.Interface
	mapper meta.ResettableRESTMapper
	dryRun bool
}

// applyResult records the outcome of applying one object, for reporting.
type applyResult struct {
	gvk  schema.GroupVersionKind
	name string
	// skipped is set when the object could not be applied during a dry run
	// because its CRD has not been established (the CRDs were not really
	// created), so its REST mapping cannot be resolved.
	skipped bool
}

func (r applyResult) String() string {
	return fmt.Sprintf("%s/%s %s", r.gvk.GroupVersion(), r.gvk.Kind, r.name)
}

// applyYAML decodes a multi-document manifest, sorts the objects so that
// dependencies (CRDs, Namespaces, RBAC) are applied before the resources that
// need them, and server-side-applies each one.
func (a *applier) applyYAML(ctx context.Context, manifest []byte) ([]applyResult, error) {
	objs, err := decodeManifest(manifest)
	if err != nil {
		return nil, err
	}
	sortObjects(objs)

	results := make([]applyResult, 0, len(objs))
	for i := range objs {
		res, err := a.applyObject(ctx, &objs[i])
		if err != nil {
			return results, err
		}
		results = append(results, res)
	}
	return results, nil
}

// applyObject server-side-applies a single object, resolving its REST mapping
// and namespacing from the live cluster's discovery information.
func (a *applier) applyObject(ctx context.Context, obj *unstructured.Unstructured) (applyResult, error) {
	gvk := obj.GroupVersionKind()
	res := applyResult{gvk: gvk, name: obj.GetName()}

	ri, err := a.resourceFor(obj)
	if err != nil {
		// During a dry run the CRDs are not really created, so a custom
		// resource whose CRD is part of this same install has no REST mapping
		// yet. Report it as skipped rather than failing the dry run.
		if a.dryRun && meta.IsNoMatchError(err) {
			res.skipped = true
			return res, nil
		}
		return res, fmt.Errorf("%s: %w", res, err)
	}

	data, err := obj.MarshalJSON()
	if err != nil {
		return res, fmt.Errorf("%s: %w", res, err)
	}

	opts := metav1.PatchOptions{FieldManager: fieldManager, Force: ptrTrue()}
	if a.dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}

	if _, err := ri.Patch(ctx, obj.GetName(), types.ApplyPatchType, data, opts); err != nil {
		// During a dry run the target namespace may not exist yet (it is created
		// earlier in this same install but not persisted under dry-run), so a
		// namespaced object cannot be validated. Defer it rather than failing.
		if a.dryRun && apierrors.IsNotFound(err) {
			res.skipped = true
			return res, nil
		}
		return res, fmt.Errorf("%s: %w", res, err)
	}
	return res, nil
}

// deleteYAML decodes a multi-document manifest and deletes the objects in
// reverse dependency order (custom resources first, CRDs/Namespaces last), so a
// dependency is never removed before the things that need it.
func (a *applier) deleteYAML(ctx context.Context, manifest []byte) ([]applyResult, error) {
	objs, err := decodeManifest(manifest)
	if err != nil {
		return nil, err
	}
	sortObjectsReverse(objs)

	results := make([]applyResult, 0, len(objs))
	for i := range objs {
		res, err := a.deleteObject(ctx, &objs[i])
		if err != nil {
			return results, err
		}
		results = append(results, res)
	}
	return results, nil
}

// deleteObject deletes a single object. It is idempotent: a missing object (or a
// missing CRD, i.e. no REST mapping) is reported as skipped, not an error.
func (a *applier) deleteObject(ctx context.Context, obj *unstructured.Unstructured) (applyResult, error) {
	gvk := obj.GroupVersionKind()
	res := applyResult{gvk: gvk, name: obj.GetName()}

	ri, err := a.resourceFor(obj)
	if err != nil {
		// The CRD (and therefore the resource type) is already gone — nothing to delete.
		if meta.IsNoMatchError(err) {
			res.skipped = true
			return res, nil
		}
		return res, fmt.Errorf("%s: %w", res, err)
	}

	opts := metav1.DeleteOptions{}
	if a.dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}

	if err := ri.Delete(ctx, obj.GetName(), opts); err != nil {
		if apierrors.IsNotFound(err) {
			res.skipped = true
			return res, nil
		}
		return res, fmt.Errorf("%s: %w", res, err)
	}
	return res, nil
}

// resourceFor resolves the dynamic resource interface (GVR + namespacing) for an
// object using the RESTMapper.
func (a *applier) resourceFor(obj *unstructured.Unstructured) (dynamic.ResourceInterface, error) {
	gvk := obj.GroupVersionKind()
	mapping, err := a.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return nil, err
	}
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		ns := obj.GetNamespace()
		if ns == "" {
			ns = metav1.NamespaceDefault
		}
		return a.dyn.Resource(mapping.Resource).Namespace(ns), nil
	}
	return a.dyn.Resource(mapping.Resource), nil
}

// waitForInstallationCRD blocks until the Installation CRD is Established so that
// the operator-config custom resources can be applied. It refreshes the
// RESTMapper once the CRD is ready so the new kinds resolve. On dry-run it is a
// no-op, since the CRDs were not actually created.
func (a *applier) waitForInstallationCRD(ctx context.Context, timeout time.Duration) error {
	if a.dryRun {
		return nil
	}

	crdGVR := schema.GroupVersionResource{
		Group:    "apiextensions.k8s.io",
		Version:  "v1",
		Resource: "customresourcedefinitions",
	}

	log.Info("Waiting for the Installation CRD to be established...")
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		crd, err := a.dyn.Resource(crdGVR).Get(ctx, installationCRDName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return crdEstablished(crd), nil
	})
	if err != nil {
		return fmt.Errorf("timed out waiting for %s to be established: %w", installationCRDName, err)
	}

	// New CRD kinds are now servable; drop cached discovery so RESTMapping can
	// resolve the operator custom resources.
	a.mapper.Reset()
	return nil
}

// crdEstablished reports whether a CustomResourceDefinition has the Established
// condition set to True.
func crdEstablished(crd *unstructured.Unstructured) bool {
	conditions, found, err := unstructured.NestedSlice(crd.Object, "status", "conditions")
	if err != nil || !found {
		return false
	}
	for _, c := range conditions {
		cond, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if cond["type"] == "Established" && cond["status"] == "True" {
			return true
		}
	}
	return false
}

// decodeManifest splits a multi-document YAML/JSON manifest into unstructured
// objects, skipping empty documents.
func decodeManifest(manifest []byte) ([]unstructured.Unstructured, error) {
	var objs []unstructured.Unstructured
	separator := yamlsep.NewYAMLDocumentSeparator(bytes.NewReader(manifest))
	for {
		doc, err := separator.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		var obj unstructured.Unstructured
		if err := yaml.Unmarshal(doc, &obj.Object); err != nil {
			return nil, fmt.Errorf("failed to parse manifest document: %w", err)
		}
		if len(obj.Object) == 0 || obj.GetKind() == "" {
			continue
		}
		objs = append(objs, obj)
	}
	return objs, nil
}

// kindApplyOrder ranks kinds so that prerequisites are applied first. Lower runs
// earlier; anything unlisted defaults to the middle, and operator custom
// resources are applied last.
var kindApplyOrder = map[string]int{
	"CustomResourceDefinition": 0,
	"Namespace":                1,
	"ServiceAccount":           2,
	"ClusterRole":              3,
	"Role":                     3,
	"ClusterRoleBinding":       4,
	"RoleBinding":              4,
	"ConfigMap":                5,
	"Secret":                   5,
	"Service":                  6,
	"Deployment":               7,
	"DaemonSet":                7,
}

// operatorConfigGroup holds the operator's config CRs, which must be applied
// after everything else (their controllers and CRDs must exist first).
const operatorConfigGroup = "operator.tigera.io"

func applyRank(obj *unstructured.Unstructured) int {
	if obj.GroupVersionKind().Group == operatorConfigGroup {
		return 100
	}
	if r, ok := kindApplyOrder[obj.GetKind()]; ok {
		return r
	}
	return 50
}

// sortObjects orders objects by apply rank, preserving the original relative
// order within a rank (stable) so manifests stay readable/deterministic.
func sortObjects(objs []unstructured.Unstructured) {
	sort.SliceStable(objs, func(i, j int) bool {
		return applyRank(&objs[i]) < applyRank(&objs[j])
	})
}

// sortObjectsReverse orders objects for deletion: the reverse of apply order, so
// custom resources go first and CRDs/Namespaces last.
func sortObjectsReverse(objs []unstructured.Unstructured) {
	sort.SliceStable(objs, func(i, j int) bool {
		return applyRank(&objs[i]) > applyRank(&objs[j])
	})
}

// waitForNamespaceGone blocks until the named namespace no longer exists, used
// to let the operator finish tearing down its managed components before the
// operator itself is removed.
func (a *applier) waitForNamespaceGone(ctx context.Context, name string, timeout time.Duration) error {
	nsGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	return wait.PollUntilContextTimeout(ctx, 3*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		_, err := a.dyn.Resource(nsGVR).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
		return false, nil
	})
}

func ptrTrue() *bool {
	b := true
	return &b
}
