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

package commands

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/install"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
)

// Uninstall removes an operator-based Calico install from the cluster.
func Uninstall(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> uninstall [--config=<CONFIG>] [--remove-crds] [--dry-run] [--wait] [--timeout=<TIMEOUT>] [-y] [--allow-version-mismatch]

Examples:
  # Remove the Calico install (operator and custom resources), keeping CRDs.
  <BINARY_NAME> uninstall

  # Preview what would be removed.
  <BINARY_NAME> uninstall --dry-run

  # Remove everything, including CRDs (deletes all Calico resources).
  <BINARY_NAME> uninstall --remove-crds

Options:
  -h --help                    Show this screen.
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
     --remove-crds             Also delete the Calico/operator CRDs. This deletes
                               ALL Calico custom resources cluster-wide and is
                               irreversible.
     --dry-run                 Print what would be removed without changing the cluster.
     --wait                    Wait for the operator to tear down the calico-system
                               namespace before removing the operator.
     --timeout=<TIMEOUT>       Maximum time to wait for teardown. [default: 5m]
  -y --yes                     Do not prompt for confirmation.
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The uninstall command removes a Calico install that was created with the
  tigera operator. It deletes the Calico custom resources first (so the operator
  tears down the components it manages), then the operator deployment and RBAC,
  and optionally the CRDs.

  The command is idempotent and requires the Kubernetes datastore.
`
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	timeout, err := time.ParseDuration(argStr(parsedArgs["--timeout"]))
	if err != nil {
		return fmt.Errorf("invalid --timeout %q: %w", argStr(parsedArgs["--timeout"]), err)
	}

	cf := argStr(parsedArgs["--config"])
	cfg, err := clientmgr.LoadClientConfig(cf)
	if err != nil {
		return err
	}
	if cfg.Spec.DatastoreType != apiconfig.Kubernetes {
		return fmt.Errorf("the uninstall command requires the Kubernetes datastore, but the configured datastore is %q", cfg.Spec.DatastoreType)
	}

	dryRun, _ := parsedArgs["--dry-run"].(bool)
	removeCRDs, _ := parsedArgs["--remove-crds"].(bool)
	doWait, _ := parsedArgs["--wait"].(bool)
	assumeYes, _ := parsedArgs["--yes"].(bool)

	// Confirm before a destructive, non-dry-run operation.
	if !dryRun && !assumeYes {
		prompt := "This will remove Calico from the cluster."
		if removeCRDs {
			prompt = "This will remove Calico AND delete all Calico custom resources cluster-wide (--remove-crds)."
		}
		if !confirm(prompt) {
			fmt.Println("Aborted.")
			return nil
		}
	}

	restConfig, _, err := k8s.CreateKubernetesClientset(&cfg.Spec)
	if err != nil {
		return fmt.Errorf("failed to build Kubernetes connection: %w", err)
	}

	return install.Uninstall(context.Background(), restConfig, install.UninstallOptions{
		DryRun:     dryRun,
		RemoveCRDs: removeCRDs,
		Wait:       doWait,
		Timeout:    timeout,
	})
}

// confirm prompts the user on stdin and returns true only for an affirmative answer.
func confirm(prompt string) bool {
	fmt.Printf("%s\nAre you sure you want to continue? [y/N]: ", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// newUninstallCommand bridges the cobra command tree to the docopt-based
// Uninstall function.
func newUninstallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove an operator-based Calico install from the cluster",
		RunE: func(cmd *cobra.Command, _ []string) error {
			synthArgs := []string{"uninstall"}
			if config, _ := cmd.Flags().GetString("config"); config != "" {
				synthArgs = append(synthArgs, "--config="+config)
			}
			if timeout, _ := cmd.Flags().GetString("timeout"); timeout != "" {
				synthArgs = append(synthArgs, "--timeout="+timeout)
			}
			if removeCRDs, _ := cmd.Flags().GetBool("remove-crds"); removeCRDs {
				synthArgs = append(synthArgs, "--remove-crds")
			}
			if dryRun, _ := cmd.Flags().GetBool("dry-run"); dryRun {
				synthArgs = append(synthArgs, "--dry-run")
			}
			if doWait, _ := cmd.Flags().GetBool("wait"); doWait {
				synthArgs = append(synthArgs, "--wait")
			}
			if assumeYes, _ := cmd.Flags().GetBool("yes"); assumeYes {
				synthArgs = append(synthArgs, "--yes")
			}
			if allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch"); allowMismatch {
				synthArgs = append(synthArgs, "--allow-version-mismatch")
			}
			return Uninstall(synthArgs)
		},
	}
	cmd.Flags().StringP("config", "c", constants.DefaultConfigPath, "Path to the file containing connection configuration in YAML or JSON format.")
	cmd.Flags().String("timeout", "5m", "Maximum time to wait for teardown.")
	cmd.Flags().Bool("remove-crds", false, "Also delete the Calico/operator CRDs (deletes all Calico resources cluster-wide).")
	cmd.Flags().Bool("dry-run", false, "Print what would be removed without changing the cluster.")
	cmd.Flags().Bool("wait", false, "Wait for the operator to tear down the calico-system namespace before removing the operator.")
	cmd.Flags().BoolP("yes", "y", false, "Do not prompt for confirmation.")
	return cmd
}
