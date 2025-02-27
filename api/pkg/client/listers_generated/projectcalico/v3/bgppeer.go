// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by lister-gen. DO NOT EDIT.

package v3

import (
	projectcalicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// BGPPeerLister helps list BGPPeers.
// All objects returned here must be treated as read-only.
type BGPPeerLister interface {
	// List lists all BGPPeers in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*projectcalicov3.BGPPeer, err error)
	// Get retrieves the BGPPeer from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*projectcalicov3.BGPPeer, error)
	BGPPeerListerExpansion
}

// bGPPeerLister implements the BGPPeerLister interface.
type bGPPeerLister struct {
	listers.ResourceIndexer[*projectcalicov3.BGPPeer]
}

// NewBGPPeerLister returns a new BGPPeerLister.
func NewBGPPeerLister(indexer cache.Indexer) BGPPeerLister {
	return &bGPPeerLister{listers.New[*projectcalicov3.BGPPeer](indexer, projectcalicov3.Resource("bgppeer"))}
}
