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

// Package install implements `calicoctl install`, which bootstraps Calico onto
// a fresh cluster via the tigera operator. The install manifests are embedded so
// the binary is self-contained and version-matched; they are staged into the
// manifests/ subdirectory by `make gen-manifests` (see manifests/generate.sh)
// and committed alongside the source.
package install

import _ "embed"

// The operator install is applied in three waves. Order matters: the CRDs must
// exist (and the Installation CRD must be Established) before the operator-config
// custom resources can be created.

//go:embed manifests/operator-crds.yaml
var operatorCRDs []byte

//go:embed manifests/tigera-operator.yaml
var operatorDeployment []byte

//go:embed manifests/custom-resources.yaml
var customResources []byte

// wave is one phase of the install, applied as a unit before the next.
type wave struct {
	name string
	yaml []byte
	// isCRD is true for the CRD wave, after which we wait for the Installation
	// CRD to become Established and reset the RESTMapper before continuing.
	isCRD bool
}

// installWaves returns the ordered phases of an operator-based install.
func installWaves() []wave {
	return []wave{
		{name: "operator CRDs", yaml: operatorCRDs, isCRD: true},
		{name: "tigera operator", yaml: operatorDeployment},
		{name: "Calico custom resources", yaml: customResources},
	}
}
