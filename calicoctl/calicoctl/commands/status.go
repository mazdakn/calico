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

	"github.com/docopt/docopt-go"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/status"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
)

// Status prints a health summary of the Calico install on the cluster.
func Status(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  <BINARY_NAME> status [--config=<CONFIG>] [--allow-version-mismatch]

Examples:
  # Show the status of the Calico install on the cluster.
  <BINARY_NAME> status

Options:
  -h --help                    Show this screen.
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The status command prints a summary of the health of the Calico install on the
  cluster: Kubernetes connectivity, the tigera operator, per-component
  TigeraStatus, and the readiness of the calico-node DaemonSet and Typha. It is
  read-only and requires the Kubernetes datastore.
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

	cf := argStr(parsedArgs["--config"])
	cfg, err := clientmgr.LoadClientConfig(cf)
	if err != nil {
		return err
	}
	if cfg.Spec.DatastoreType != apiconfig.Kubernetes {
		return fmt.Errorf("the status command requires the Kubernetes datastore, but the configured datastore is %q", cfg.Spec.DatastoreType)
	}

	restConfig, _, err := k8s.CreateKubernetesClientset(&cfg.Spec)
	if err != nil {
		return fmt.Errorf("failed to build Kubernetes connection: %w", err)
	}

	return status.Status(context.Background(), restConfig, string(cfg.Spec.DatastoreType))
}

// newStatusCommand bridges the cobra command tree to the docopt-based Status function.
func newStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the status of the Calico install on the cluster",
		RunE: func(cmd *cobra.Command, _ []string) error {
			synthArgs := []string{"status"}
			if config, _ := cmd.Flags().GetString("config"); config != "" {
				synthArgs = append(synthArgs, "--config="+config)
			}
			if allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch"); allowMismatch {
				synthArgs = append(synthArgs, "--allow-version-mismatch")
			}
			return Status(synthArgs)
		},
	}
	cmd.Flags().StringP("config", "c", constants.DefaultConfigPath, "Path to the file containing connection configuration in YAML or JSON format.")
	return cmd
}
