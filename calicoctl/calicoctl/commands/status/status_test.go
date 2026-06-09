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

package status

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

func fakeKube() kubernetes.Interface {
	return kubefake.NewClientset()
}

func newKubeWithDaemonSet(ns string) kubernetes.Interface {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: calicoNodeDaemonSet, Namespace: ns},
	}
	return kubefake.NewClientset(ds)
}

func TestTigeraStatusConditions(t *testing.T) {
	ts := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"conditions": []any{
				map[string]any{"type": "Available", "status": "True"},
				map[string]any{"type": "Degraded", "status": "False"},
			},
		},
	}}
	avail, prog, degr := tigeraStatusConditions(ts)
	if avail != "True" {
		t.Errorf("available = %q, want True", avail)
	}
	if prog != "-" {
		t.Errorf("progressing = %q, want - (absent)", prog)
	}
	if degr != "False" {
		t.Errorf("degraded = %q, want False", degr)
	}
}

func TestDetectDataplaneNamespace(t *testing.T) {
	t.Run("prefers calico-system", func(t *testing.T) {
		kube := newKubeWithDaemonSet(calicoSystemNamespace)
		if ns := detectDataplaneNamespace(context.Background(), kube); ns != calicoSystemNamespace {
			t.Errorf("namespace = %q, want calico-system", ns)
		}
	})
	t.Run("falls back to kube-system", func(t *testing.T) {
		kube := newKubeWithDaemonSet(kubeSystemNamespace)
		if ns := detectDataplaneNamespace(context.Background(), kube); ns != kubeSystemNamespace {
			t.Errorf("namespace = %q, want kube-system", ns)
		}
	})
	t.Run("none found", func(t *testing.T) {
		kube := fakeKube()
		if ns := detectDataplaneNamespace(context.Background(), kube); ns != "" {
			t.Errorf("namespace = %q, want empty", ns)
		}
	})
}

func TestReportDataplane_Degraded(t *testing.T) {
	kube := newKubeWithDaemonSet(calicoSystemNamespace)
	// Mark the DaemonSet as not fully ready.
	ds, _ := kube.AppsV1().DaemonSets(calicoSystemNamespace).Get(context.Background(), calicoNodeDaemonSet, metav1.GetOptions{})
	ds.Status.DesiredNumberScheduled = 3
	ds.Status.NumberReady = 1
	_, _ = kube.AppsV1().DaemonSets(calicoSystemNamespace).UpdateStatus(context.Background(), ds, metav1.UpdateOptions{})

	var sb strings.Builder
	reportDataplane(context.Background(), &sb, kube, calicoSystemNamespace)
	out := sb.String()
	if !strings.Contains(out, "DEGRADED") || !strings.Contains(out, "1/3") {
		t.Errorf("unexpected dataplane report: %q", out)
	}
}
