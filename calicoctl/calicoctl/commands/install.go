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
	"context"
	"fmt"
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

// Install bootstraps Calico onto a fresh cluster via the tigera operator.
func Install(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> install [--type=<TYPE>] [--config=<CONFIG>] [--dry-run] [--wait] [--timeout=<TIMEOUT>] [--allow-version-mismatch]

Examples:
  # Install Calico on a fresh cluster using the tigera operator.
  <BINARY_NAME> install

  # Preview the resources that would be applied, without changing the cluster.
  <BINARY_NAME> install --dry-run

  # Install and wait for the operator to become available.
  <BINARY_NAME> install --wait

Options:
  -h --help                    Show this screen.
     --type=<TYPE>             Install method. Only "operator" is supported.
                               [default: operator]
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
     --dry-run                 Print the resources that would be applied without
                               making any changes to the cluster.
     --wait                    Wait for the tigera operator deployment to become
                               available before returning.
     --timeout=<TIMEOUT>       Maximum time to wait for readiness conditions.
                               [default: 5m]
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The install command deploys Calico onto a fresh Kubernetes cluster using the
  tigera operator. It applies the operator CRDs, the operator deployment, and the
  default Calico Installation custom resource, after which the operator reconciles
  the rest of the Calico components.

  The command uses server-side apply and is safe to re-run; it reconciles an
  existing install rather than failing. It requires the Kubernetes datastore.
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

	installType := strings.ToLower(argStr(parsedArgs["--type"]))
	switch installType {
	case "operator":
		// Supported.
	case "manifest":
		return fmt.Errorf("--type=manifest is not yet supported; only operator-based install is available")
	default:
		return fmt.Errorf("unsupported --type %q; only \"operator\" is supported", installType)
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
		return fmt.Errorf("the install command requires the Kubernetes datastore, but the configured datastore is %q", cfg.Spec.DatastoreType)
	}

	// Reuse libcalico-go's client construction to honour the same kubeconfig /
	// endpoint / credential resolution as every other calicoctl command.
	restConfig, _, err := k8s.CreateKubernetesClientset(&cfg.Spec)
	if err != nil {
		return fmt.Errorf("failed to build Kubernetes connection: %w", err)
	}

	dryRun, _ := parsedArgs["--dry-run"].(bool)
	doWait, _ := parsedArgs["--wait"].(bool)

	return install.Install(context.Background(), restConfig, install.Options{
		DryRun:  dryRun,
		Wait:    doWait,
		Timeout: timeout,
	})
}

// newInstallCommand bridges the cobra command tree to the docopt-based Install
// function, mirroring the pattern used by the other commands.
func newInstallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install Calico on a fresh cluster via the tigera operator",
		RunE: func(cmd *cobra.Command, _ []string) error {
			synthArgs := []string{"install"}
			if t, _ := cmd.Flags().GetString("type"); t != "" {
				synthArgs = append(synthArgs, "--type="+t)
			}
			if config, _ := cmd.Flags().GetString("config"); config != "" {
				synthArgs = append(synthArgs, "--config="+config)
			}
			if timeout, _ := cmd.Flags().GetString("timeout"); timeout != "" {
				synthArgs = append(synthArgs, "--timeout="+timeout)
			}
			if dryRun, _ := cmd.Flags().GetBool("dry-run"); dryRun {
				synthArgs = append(synthArgs, "--dry-run")
			}
			if doWait, _ := cmd.Flags().GetBool("wait"); doWait {
				synthArgs = append(synthArgs, "--wait")
			}
			if allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch"); allowMismatch {
				synthArgs = append(synthArgs, "--allow-version-mismatch")
			}
			return Install(synthArgs)
		},
	}
	cmd.Flags().String("type", "operator", `Install method. Only "operator" is supported.`)
	cmd.Flags().StringP("config", "c", constants.DefaultConfigPath, "Path to the file containing connection configuration in YAML or JSON format.")
	cmd.Flags().String("timeout", "5m", "Maximum time to wait for readiness conditions.")
	cmd.Flags().Bool("dry-run", false, "Print the resources that would be applied without changing the cluster.")
	cmd.Flags().Bool("wait", false, "Wait for the tigera operator deployment to become available before returning.")
	return cmd
}
