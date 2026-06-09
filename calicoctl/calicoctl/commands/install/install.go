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
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	memory "k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
)

const (
	operatorNamespace      = "tigera-operator"
	operatorDeploymentName = "tigera-operator"
)

// Options controls an install run.
type Options struct {
	// DryRun applies server-side with DryRunAll, so nothing is persisted.
	DryRun bool
	// Wait blocks until the operator Deployment becomes Available.
	Wait bool
	// Timeout bounds the CRD-established wait and the operator-ready wait.
	Timeout time.Duration
}

// Install bootstraps Calico onto the cluster reachable via cfg, using the tigera
// operator. It is idempotent: it server-side-applies the embedded manifests, so
// re-running reconciles rather than failing.
func Install(ctx context.Context, cfg *rest.Config, opts Options) error {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Minute
	}

	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create dynamic client: %w", err)
	}
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create discovery client: %w", err)
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))

	if existing, err := installDetected(ctx, kube); err != nil {
		return err
	} else if existing {
		log.Warnf("An existing %q namespace was found; re-applying the install (this is safe and idempotent).", operatorNamespace)
	}

	a := &applier{dyn: dyn, mapper: mapper, dryRun: opts.DryRun}

	if opts.DryRun {
		fmt.Println("Running in --dry-run mode: no changes will be made to the cluster.")
	}

	for _, w := range installWaves() {
		fmt.Printf("Applying %s...\n", w.name)
		results, err := a.applyYAML(ctx, w.yaml)
		if err != nil {
			return fmt.Errorf("failed while applying %s: %w", w.name, err)
		}
		applied, skipped := 0, 0
		for _, r := range results {
			if r.skipped {
				skipped++
				fmt.Printf("  would apply (after CRDs are established): %s\n", r)
				continue
			}
			applied++
			log.Debugf("  applied %s", r)
		}
		fmt.Printf("  applied %d resource(s)\n", applied)
		if skipped > 0 {
			fmt.Printf("  %d resource(s) deferred in dry-run (depend on CRDs/namespaces not yet created)\n", skipped)
		}

		if w.isCRD {
			if err := a.waitForInstallationCRD(ctx, opts.Timeout); err != nil {
				return err
			}
		}
	}

	if opts.DryRun {
		fmt.Println("Dry run complete. Calico was not installed.")
		return nil
	}

	if opts.Wait {
		if err := waitForOperator(ctx, kube, opts.Timeout); err != nil {
			return err
		}
	}

	printNextSteps(opts.Wait)
	return nil
}

// installDetected reports whether the tigera-operator namespace already exists.
func installDetected(ctx context.Context, kube kubernetes.Interface) (bool, error) {
	_, err := kube.CoreV1().Namespaces().Get(ctx, operatorNamespace, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check for an existing install: %w", err)
	}
	return true, nil
}

// waitForOperator blocks until the tigera-operator Deployment reports at least
// one available replica.
func waitForOperator(ctx context.Context, kube kubernetes.Interface, timeout time.Duration) error {
	fmt.Println("Waiting for the tigera operator to become available...")
	err := wait.PollUntilContextTimeout(ctx, 3*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		dep, err := kube.AppsV1().Deployments(operatorNamespace).Get(ctx, operatorDeploymentName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return dep.Status.AvailableReplicas > 0, nil
	})
	if err != nil {
		return fmt.Errorf("timed out waiting for the tigera operator to become available: %w", err)
	}
	fmt.Println("The tigera operator is available.")
	return nil
}

func printNextSteps(waited bool) {
	fmt.Println()
	fmt.Println("Calico install applied via the tigera operator.")
	if !waited {
		fmt.Println("The operator is now reconciling the cluster. This can take a few minutes.")
	}
	fmt.Println("Check progress with:")
	fmt.Println("  calicoctl get tigerastatus")
	fmt.Println("  kubectl get installation default -o yaml")
}
