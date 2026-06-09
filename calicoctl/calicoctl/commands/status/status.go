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

// Package status implements `calicoctl status`, a read-only summary of the
// health of a Calico install on a Kubernetes cluster.
package status

import (
	"context"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	operatorNamespace      = "tigera-operator"
	operatorDeploymentName = "tigera-operator"
	calicoSystemNamespace  = "calico-system"
	kubeSystemNamespace    = "kube-system"
	calicoNodeDaemonSet    = "calico-node"
	typhaDeploymentName    = "calico-typha"
)

var tigeraStatusGVR = schema.GroupVersionResource{
	Group:    "operator.tigera.io",
	Version:  "v1",
	Resource: "tigerastatuses",
}

// Status prints a health summary for the Calico install reachable via cfg.
// datastoreType is the configured Calico datastore ("kubernetes" or "etcdv3").
func Status(ctx context.Context, cfg *rest.Config, datastoreType string) error {
	return statusTo(ctx, os.Stdout, cfg, datastoreType)
}

func statusTo(ctx context.Context, out io.Writer, cfg *rest.Config, datastoreType string) error {
	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create dynamic client: %w", err)
	}

	// Connectivity: listing the server version confirms the API is reachable.
	ver, err := kube.Discovery().ServerVersion()
	if err != nil {
		return fmt.Errorf("unable to reach the Kubernetes API server: %w", err)
	}
	fmt.Fprintf(out, "Cluster connectivity: OK (Kubernetes %s)\n", ver.GitVersion)
	fmt.Fprintf(out, "Calico datastore:     %s\n\n", datastoreType)

	// Determine which namespace holds the Calico data-plane (operator installs
	// use calico-system; manifest installs use kube-system).
	dataplaneNS := detectDataplaneNamespace(ctx, kube)

	reportOperator(ctx, out, kube)
	reportTigeraStatus(ctx, out, dyn)
	reportDataplane(ctx, out, kube, dataplaneNS)

	return nil
}

// detectDataplaneNamespace returns the namespace running calico-node, preferring
// the operator-managed calico-system namespace.
func detectDataplaneNamespace(ctx context.Context, kube kubernetes.Interface) string {
	for _, ns := range []string{calicoSystemNamespace, kubeSystemNamespace} {
		if _, err := kube.AppsV1().DaemonSets(ns).Get(ctx, calicoNodeDaemonSet, metav1.GetOptions{}); err == nil {
			return ns
		}
	}
	return ""
}

func reportOperator(ctx context.Context, out io.Writer, kube kubernetes.Interface) {
	dep, err := kube.AppsV1().Deployments(operatorNamespace).Get(ctx, operatorDeploymentName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		fmt.Fprintln(out, "Tigera operator:      not installed (manifest-based install or not installed)")
		fmt.Fprintln(out)
		return
	}
	if err != nil {
		fmt.Fprintf(out, "Tigera operator:      error: %v\n\n", err)
		return
	}
	state := "available"
	if dep.Status.AvailableReplicas == 0 {
		state = "NOT available"
	}
	fmt.Fprintf(out, "Tigera operator:      %s (%d/%d replicas ready)\n\n",
		state, dep.Status.AvailableReplicas, dep.Status.Replicas)
}

func reportTigeraStatus(ctx context.Context, out io.Writer, dyn dynamic.Interface) {
	list, err := dyn.Resource(tigeraStatusGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		// No TigeraStatus CRD / not an operator install — nothing to report.
		return
	}
	if len(list.Items) == 0 {
		return
	}

	fmt.Fprintln(out, "Tigera status:")
	w := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "  COMPONENT\tAVAILABLE\tPROGRESSING\tDEGRADED")
	for i := range list.Items {
		item := &list.Items[i]
		avail, prog, degr := tigeraStatusConditions(item)
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", item.GetName(), avail, prog, degr)
	}
	_ = w.Flush()
	fmt.Fprintln(out)
}

// tigeraStatusConditions extracts the Available/Progressing/Degraded condition
// statuses from a TigeraStatus object.
func tigeraStatusConditions(ts *unstructured.Unstructured) (available, progressing, degraded string) {
	available, progressing, degraded = "-", "-", "-"
	conditions, found, err := unstructured.NestedSlice(ts.Object, "status", "conditions")
	if err != nil || !found {
		return
	}
	for _, c := range conditions {
		cond, ok := c.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := cond["type"].(string)
		st, _ := cond["status"].(string)
		switch typ {
		case "Available":
			available = st
		case "Progressing":
			progressing = st
		case "Degraded":
			degraded = st
		}
	}
	return
}

func reportDataplane(ctx context.Context, out io.Writer, kube kubernetes.Interface, ns string) {
	if ns == "" {
		fmt.Fprintln(out, "Calico node:          calico-node DaemonSet not found")
		return
	}

	ds, err := kube.AppsV1().DaemonSets(ns).Get(ctx, calicoNodeDaemonSet, metav1.GetOptions{})
	if err != nil {
		fmt.Fprintf(out, "Calico node:          error: %v\n", err)
		return
	}
	desired := ds.Status.DesiredNumberScheduled
	ready := ds.Status.NumberReady
	state := "OK"
	if ready < desired || desired == 0 {
		state = "DEGRADED"
	}
	fmt.Fprintf(out, "Calico node:          %s (%d/%d nodes ready, namespace %q)\n", state, ready, desired, ns)

	// Typha is optional.
	if typha, err := kube.AppsV1().Deployments(ns).Get(ctx, typhaDeploymentName, metav1.GetOptions{}); err == nil {
		fmt.Fprintf(out, "Calico Typha:         %d/%d replicas ready\n", typha.Status.ReadyReplicas, typha.Status.Replicas)
	}
}
