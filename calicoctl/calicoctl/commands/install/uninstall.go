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
	"k8s.io/client-go/discovery"
	memory "k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
)

// calicoManagedNamespace is the namespace the operator creates for the Calico
// components it manages; uninstall waits for it to disappear so those components
// are torn down before the operator itself is removed.
const calicoManagedNamespace = "calico-system"

// UninstallOptions controls an uninstall run.
type UninstallOptions struct {
	// DryRun deletes server-side with DryRunAll, so nothing is actually removed.
	DryRun bool
	// RemoveCRDs additionally deletes the Calico/operator CRDs. This deletes ALL
	// Calico custom resources of those types cluster-wide and is irreversible.
	RemoveCRDs bool
	// Wait blocks for the operator to tear down the calico-system namespace
	// before the operator is removed.
	Wait bool
	// Timeout bounds the teardown wait.
	Timeout time.Duration
}

// Uninstall removes an operator-based Calico install. It is the inverse of
// Install and deletes in dependency order: the operator-config custom resources
// first (so the operator tears down the components it manages), then the
// operator deployment and RBAC, and optionally the CRDs. It is idempotent:
// resources that are already gone are skipped.
func Uninstall(ctx context.Context, cfg *rest.Config, opts UninstallOptions) error {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Minute
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
	a := &applier{dyn: dyn, mapper: mapper, dryRun: opts.DryRun}

	if opts.DryRun {
		fmt.Println("Running in --dry-run mode: no changes will be made to the cluster.")
	}

	// 1. Delete the operator-config CRs so the operator deletes the components
	//    it manages (the calico-system namespace and everything in it).
	fmt.Println("Removing Calico custom resources...")
	if err := a.deleteAndReport(ctx, customResources); err != nil {
		return err
	}

	// 2. Let the operator finish tearing down its managed namespace.
	if opts.Wait && !opts.DryRun {
		fmt.Printf("Waiting for the operator to tear down the %q namespace...\n", calicoManagedNamespace)
		if err := a.waitForNamespaceGone(ctx, calicoManagedNamespace, opts.Timeout); err != nil {
			return fmt.Errorf("timed out waiting for %q to be removed: %w", calicoManagedNamespace, err)
		}
	}

	// 3. Delete the operator deployment, RBAC and namespace.
	fmt.Println("Removing the tigera operator...")
	if err := a.deleteAndReport(ctx, operatorDeployment); err != nil {
		return err
	}

	// 4. Optionally delete the CRDs (removes all Calico custom resources too).
	if opts.RemoveCRDs {
		log.Warn("Removing Calico CRDs; this deletes all Calico custom resources cluster-wide.")
		fmt.Println("Removing operator CRDs...")
		if err := a.deleteAndReport(ctx, operatorCRDs); err != nil {
			return err
		}
	}

	if opts.DryRun {
		fmt.Println("Dry run complete. Nothing was removed.")
		return nil
	}

	fmt.Println()
	fmt.Println("Calico uninstall complete.")
	if !opts.RemoveCRDs {
		fmt.Println("Calico CRDs were left in place; re-run with --remove-crds to delete them.")
	}
	return nil
}

// deleteAndReport deletes a manifest and prints a one-line summary.
func (a *applier) deleteAndReport(ctx context.Context, manifest []byte) error {
	results, err := a.deleteYAML(ctx, manifest)
	if err != nil {
		return err
	}
	deleted, skipped := 0, 0
	for _, r := range results {
		if r.skipped {
			skipped++
			continue
		}
		deleted++
		log.Debugf("  deleted %s", r)
	}
	fmt.Printf("  deleted %d resource(s)", deleted)
	if skipped > 0 {
		fmt.Printf(" (%d already absent)", skipped)
	}
	fmt.Println()
	return nil
}
