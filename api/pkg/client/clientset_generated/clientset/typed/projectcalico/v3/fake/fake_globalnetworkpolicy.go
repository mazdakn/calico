// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	projectcalicov3 "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	gentype "k8s.io/client-go/gentype"
)

// fakeGlobalNetworkPolicies implements GlobalNetworkPolicyInterface
type fakeGlobalNetworkPolicies struct {
	*gentype.FakeClientWithList[*v3.GlobalNetworkPolicy, *v3.GlobalNetworkPolicyList]
	Fake *FakeProjectcalicoV3
}

func newFakeGlobalNetworkPolicies(fake *FakeProjectcalicoV3) projectcalicov3.GlobalNetworkPolicyInterface {
	return &fakeGlobalNetworkPolicies{
		gentype.NewFakeClientWithList[*v3.GlobalNetworkPolicy, *v3.GlobalNetworkPolicyList](
			fake.Fake,
			"",
			v3.SchemeGroupVersion.WithResource("globalnetworkpolicies"),
			v3.SchemeGroupVersion.WithKind("GlobalNetworkPolicy"),
			func() *v3.GlobalNetworkPolicy { return &v3.GlobalNetworkPolicy{} },
			func() *v3.GlobalNetworkPolicyList { return &v3.GlobalNetworkPolicyList{} },
			func(dst, src *v3.GlobalNetworkPolicyList) { dst.ListMeta = src.ListMeta },
			func(list *v3.GlobalNetworkPolicyList) []*v3.GlobalNetworkPolicy {
				return gentype.ToPointerSlice(list.Items)
			},
			func(list *v3.GlobalNetworkPolicyList, items []*v3.GlobalNetworkPolicy) {
				list.Items = gentype.FromPointerSlice(items)
			},
		),
		fake,
	}
}
