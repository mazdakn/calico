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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/convert"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	yamlsep "github.com/projectcalico/calico/calicoctl/calicoctl/util/yaml"
	validatorv3 "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
)

// newConvertCommand bridges the cobra command tree to the docopt-based Convert
// function, mirroring the pattern used by the CRUD commands.
func newConvertCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "convert",
		Short: "Convert third-party (e.g. Cilium) network policies to Calico resources",
		RunE: func(cmd *cobra.Command, _ []string) error {
			synthArgs := []string{"convert"}
			if from, _ := cmd.Flags().GetString("from"); from != "" {
				synthArgs = append(synthArgs, "--from="+from)
			}
			if filename, _ := cmd.Flags().GetString("filename"); filename != "" {
				synthArgs = append(synthArgs, "--filename="+filename)
			}
			if output, _ := cmd.Flags().GetString("output"); output != "" {
				synthArgs = append(synthArgs, "--output="+output)
			}
			if recursive, _ := cmd.Flags().GetBool("recursive"); recursive {
				synthArgs = append(synthArgs, "--recursive")
			}
			if allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch"); allowMismatch {
				synthArgs = append(synthArgs, "--allow-version-mismatch")
			}
			return Convert(synthArgs)
		},
	}
	cmd.Flags().String("from", "cilium", "Source policy format to convert from. Supported: cilium.")
	cmd.Flags().StringP("filename", "f", "", "Filename to load the resources to convert. Use '-' for stdin.")
	cmd.Flags().StringP("output", "o", "yaml", "Output format. One of: yaml, json.")
	cmd.Flags().BoolP("recursive", "R", false, "Process the filename specified in -f recursively.")
	return cmd
}

// Convert reads third-party network policy resources and prints the equivalent
// Calico resources. It runs entirely offline (no datastore connection).
func Convert(args []string) error {
	doc := `Usage:
  <BINARY_NAME> convert --from=<FORMAT> --filename=<FILENAME> [--output=<OUTPUT>] [--recursive] [--allow-version-mismatch]

Examples:
  # Convert Cilium policies in policy.yaml to Calico policies.
  <BINARY_NAME> convert --from=cilium -f ./policy.yaml

  # Convert Cilium policies from stdin and apply the result.
  cat cilium.yaml | <BINARY_NAME> convert --from=cilium -f - | <BINARY_NAME> apply -f -

Options:
  -h --help                    Show this screen.
     --from=<FORMAT>           Source policy format to convert from. Supported: cilium.
  -f --filename=<FILENAME>     Filename to use to load the resources to convert. If set
                               to "-" loads from stdin. If filename is a directory, this
                               command is invoked for each .json, .yaml and .yml file
                               within that directory.
  -o --output=<OUTPUT>         Output format. One of: yaml, json. [default: yaml]
  -R --recursive               Process the filename specified in -f or --filename recursively.
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The convert command translates network policies written for another CNI into
  the equivalent Calico resources, printing them to stdout. It does not connect
  to a datastore and does not modify the cluster; pipe its output to
  '<BINARY_NAME> apply -f -' to install the converted policies.

  Cilium CiliumNetworkPolicy resources convert to Calico NetworkPolicy, and
  CiliumClusterwideNetworkPolicy resources convert to Calico GlobalNetworkPolicy.

  Conversion is conservative: any Cilium construct that cannot be faithfully
  represented in Calico (for example toFQDNs, toServices, Kafka/DNS layer-7
  rules, or non-"world" reserved entities) causes the affected policy to fail
  the conversion with a descriptive error, and no output is produced. This
  ensures the generated policies never silently differ in meaning from the
  originals.
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

	from := strings.ToLower(argStr(parsedArgs["--from"]))
	if from != "cilium" {
		return fmt.Errorf("unsupported --from format %q; supported formats: cilium", argStr(parsedArgs["--from"]))
	}

	output := strings.ToLower(argStr(parsedArgs["--output"]))
	var printer common.ResourcePrinter
	switch output {
	case "", "yaml", "yml":
		printer = common.ResourcePrinterYAML{}
	case "json":
		printer = common.ResourcePrinterJSON{}
	default:
		return fmt.Errorf("unrecognized output format %q; expected yaml or json", output)
	}

	filename := argStr(parsedArgs["--filename"])
	recursive, _ := parsedArgs["--recursive"].(bool)

	docs, err := readDocuments(filename, recursive)
	if err != nil {
		return err
	}

	// Convert every document, accumulating errors so the user sees all problems
	// at once. On any error we emit nothing — a partial file would be misleading.
	var resources []runtime.Object
	var convErrs []string
	for _, d := range docs {
		objs, err := convert.FromCiliumYAML(d.data)
		if err != nil {
			convErrs = append(convErrs, fmt.Sprintf("%s: %v", d.source, err))
			continue
		}
		for _, o := range objs {
			if err := validatorv3.Validate(o); err != nil {
				convErrs = append(convErrs, fmt.Sprintf("%s: converted resource failed validation: %v", d.source, err))
				continue
			}
			resources = append(resources, o)
		}
	}

	if len(convErrs) > 0 {
		return fmt.Errorf("failed to convert %d of %d resource(s):\n  %s",
			len(convErrs), len(docs), strings.Join(convErrs, "\n  "))
	}
	if len(resources) == 0 {
		return fmt.Errorf("no convertible resources found")
	}

	return printer.Print(nil, resources)
}

// inputDoc is a single YAML/JSON document together with the source it came from,
// for error reporting.
type inputDoc struct {
	source string
	data   []byte
}

// readDocuments loads and splits the input into individual YAML/JSON documents.
// filename may be "-" (stdin), a single file, or a directory.
func readDocuments(filename string, recursive bool) ([]inputDoc, error) {
	if filename == "" {
		return nil, fmt.Errorf("no filename specified; use -f/--filename (use '-' for stdin)")
	}

	if filename == "-" {
		return splitDocuments("<stdin>", os.Stdin)
	}

	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return readFileDocuments(filename)
	}

	// Directory: process .yaml/.yml/.json files, recursing only when asked.
	var docs []inputDoc
	walk := func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != filename && !recursive {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yaml", ".yml", ".json":
			fileDocs, err := readFileDocuments(path)
			if err != nil {
				return err
			}
			docs = append(docs, fileDocs...)
		}
		return nil
	}
	if err := filepath.WalkDir(filename, walk); err != nil {
		return nil, err
	}
	return docs, nil
}

func readFileDocuments(path string) ([]inputDoc, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return splitDocuments(path, f)
}

// splitDocuments breaks a reader into individual documents using the same
// multi-document YAML separator the resource loader uses.
func splitDocuments(source string, r io.Reader) ([]inputDoc, error) {
	var docs []inputDoc
	separator := yamlsep.NewYAMLDocumentSeparator(r)
	for {
		b, err := separator.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(strings.TrimSpace(string(b))) == 0 {
			continue
		}
		// Copy: the separator's scanner reuses its buffer on the next Next(),
		// so retaining the returned slice would corrupt earlier documents.
		data := append([]byte(nil), b...)
		docs = append(docs, inputDoc{source: source, data: data})
	}
	log.WithField("source", source).WithField("numDocs", len(docs)).Debug("Split input into documents")
	return docs, nil
}

func argStr(v any) string {
	s, _ := v.(string)
	return s
}
