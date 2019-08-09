// Copyright (c) 2019 Bell Canada, Pantheon Technologies and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package srv6

import (
	"fmt"
	"net"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/sfc/config"
	"github.com/contiv/vpp/plugins/sfc/renderer"
	"github.com/contiv/vpp/plugins/statscollector"
	"github.com/ligato/cn-infra/logging"
	vpp_l3 "github.com/ligato/vpp-agent/api/models/vpp/l3"
	vpp_srv6 "github.com/ligato/vpp-agent/api/models/vpp/srv6"
	"github.com/ligato/vpp-agent/pkg/models"
	"github.com/pkg/errors"
)

const (
	ipv4HostPrefix   = "/32"
	ipv6HostPrefix   = "/128"
	ipv6PodSidPrefix = "/128"
	ipv6AddrAny      = "::"
)

// Renderer implements SRv6 - SRv6 rendering of SFC in Contiv-VPP.
type Renderer struct {
	Deps
}

// Deps lists dependencies of the Renderer.
type Deps struct {
	Log              logging.Logger
	Config           *config.Config
	ContivConf       contivconf.API
	IPAM             ipam.API
	IPNet            ipnet.API
	UpdateTxnFactory func(change string) (txn controller.UpdateOperations)
	ResyncTxnFactory func() (txn controller.ResyncOperations)
	Stats            statscollector.API /* used for exporting the statistics */
}

// Init initializes the renderer.
func (rndr *Renderer) Init(snatOnly bool) error {
	if rndr.Config == nil {
		rndr.Config = config.DefaultConfig()
	}
	return nil
}

// AfterInit does nothing for this renderer.
func (rndr *Renderer) AfterInit() error {
	return nil
}

// AddChain is called for a newly added service function chain.
func (rndr *Renderer) AddChain(sfc *renderer.ContivSFC) error {
	rndr.Log.Infof("Add SFC: %v", sfc)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("add SFC '%s'", sfc.Name))

	config, err := rndr.renderChain(sfc)
	if err != nil {
		return errors.Wrapf(err, "can't add chain %v", sfc)
	}
	controller.PutAll(txn, config)

	return nil
}

// UpdateChain informs renderer about a change in the configuration or in the state of a service function chain.
func (rndr *Renderer) UpdateChain(oldSFC, newSFC *renderer.ContivSFC) error {
	rndr.Log.Infof("Update SFC: %v", newSFC)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("update SFC '%s'", newSFC.Name))

	oldConfig, err := rndr.renderChain(oldSFC)
	if err != nil {
		return errors.Wrapf(err, "can't remove old chain %v", oldSFC)
	}
	newConfig, err := rndr.renderChain(newSFC)
	if err != nil {
		return errors.Wrapf(err, "can't add new chain %v", newSFC)
	}

	controller.DeleteAll(txn, oldConfig)
	controller.PutAll(txn, newConfig)

	return nil
}

// DeleteChain is called for every removed service function chain.
func (rndr *Renderer) DeleteChain(sfc *renderer.ContivSFC) error {
	rndr.Log.Infof("Delete SFC: %v", sfc)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("delete SFC chain '%s'", sfc.Name))

	config, err := rndr.renderChain(sfc)
	if err != nil {
		return errors.Wrapf(err, "can't delete chain %v", sfc)
	}
	controller.DeleteAll(txn, config)

	return nil
}

// Resync completely replaces the current configuration with the provided full state of service chains.
func (rndr *Renderer) Resync(resyncEv *renderer.ResyncEventData) error {
	txn := rndr.ResyncTxnFactory()

	// resync SFC configuration
	for _, sfc := range resyncEv.Chains {
		config, err := rndr.renderChain(sfc)
		if err != nil {
			return errors.Wrapf(err, "can't resync chain %v", sfc)
		}
		controller.PutAll(txn, config)
	}

	return nil
}

// Close deallocates resources held by the renderer.
func (rndr *Renderer) Close() error {
	return nil
}

func (rndr *Renderer) chainEndAddress(sfc *renderer.ContivSFC) (podIP *net.IPNet) {
	podIP = nil

	// FIXME rewrite to get IP address from end pod/interface only

	for _, chain := range sfc.Chain {
		for _, pod := range chain.Pods {
			podIP = rndr.IPAM.GetPodIP(pod.ID)
		}
	}

	return podIP
}

// renderChain renders Contiv SFC to VPP configuration.
func (rndr *Renderer) renderChain(sfc *renderer.ContivSFC) (config controller.KeyValuePairs, err error) {
	// TODO remove all debug logging later
	rndr.Log.Debugf("[DEBUG]sfc: %v", sfc)

	config = make(controller.KeyValuePairs)
	if sfc == nil {
		return config, errors.New("can't create sfc chain configuration due to missing sfc information")
	}
	if sfc.Chain == nil || len(sfc.Chain) == 0 {
		return config, errors.New("can't create sfc chain configuration due to missing chain information")
	}
	if len(sfc.Chain) < 2 {
		return config, errors.New("can't create sfc chain configuration due to missing information on start and end chain links (chain has less than 2 links)")
	}

	bsid := rndr.IPAM.BsidForSFCPolicy(sfc.Name)
	steering := &vpp_srv6.Steering{
		Name: "forK8sSFC-" + sfc.Name,
		PolicyRef: &vpp_srv6.Steering_PolicyBsid{
			PolicyBsid: bsid.String(),
		},
		Traffic: &vpp_srv6.Steering_L2Traffic_{
			L2Traffic: &vpp_srv6.Steering_L2Traffic{
				InterfaceName: sfc.Chain[0].Pods[0].OutputInterface,
			},
		},
	}
	config[models.Key(steering)] = steering

	// create Srv6 policy with segment list for each backend (loadbalancing and packet switching part)
	// Ignore first and last podIP
	// Fist podIP represent start (steering) function to SRv6
	// Last podIP represent end function to SRv6
	segmentLists := make([]*vpp_srv6.Policy_SegmentList, 0)
	segments := make([]string, 0)
	for id, chain := range sfc.Chain {
		if id == 0 {
			continue
		}

		for _, pod := range chain.Pods {
			rndr.Log.Debugf("[DEBUG] id :%v, len chain: %v Pods: %v",
				id, len(sfc.Chain), rndr.IPAM.GetPodIP(pod.ID))
			podIP := rndr.IPAM.GetPodIP(pod.ID)
			if id == (len(sfc.Chain) - 1) {
				segments = append(segments, rndr.IPAM.SidForSFCEndLocalsid(podIP.IP).String())
			} else {
				segments = append(segments, rndr.IPAM.SidForSFCServiceFunctionLocalsid(sfc.Name, podIP.IP).String())
			}
		}
		segmentLists = append(segmentLists,
			&vpp_srv6.Policy_SegmentList{
				Weight:   1,
				Segments: segments,
			})
	}

	policy := &vpp_srv6.Policy{
		InstallationVrfId: rndr.ContivConf.GetRoutingConfig().MainVRFID,
		Bsid:              bsid.String(),
		SegmentLists:      segmentLists,
		SprayBehaviour:    false, // loadbalance packets and not duplicate(spray) it to all segment lists
		SrhEncapsulation:  true,
	}
	config[models.Key(policy)] = policy

	chainEndAddress := rndr.chainEndAddress(sfc)
	route := &vpp_l3.Route{
		Type:        vpp_l3.Route_INTER_VRF,
		DstNetwork:  rndr.IPAM.SidForSFCEndLocalsid(chainEndAddress.IP.To16()).String() + ipv6PodSidPrefix,
		VrfId:       rndr.ContivConf.GetRoutingConfig().MainVRFID,
		ViaVrfId:    rndr.ContivConf.GetRoutingConfig().PodVRFID,
		NextHopAddr: ipv6AddrAny,
	}
	key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	config[key] = route

	// getting more info about local backend
	podID, found := rndr.IPAM.GetPodFromIP(chainEndAddress.IP)
	if !found {
		rndr.Log.Warnf("Unable to get pod info for backend IP %v", chainEndAddress.IP)
		//TODO handle
		//continue
	}
	vppIfName, _, _, exists := rndr.IPNet.GetPodIfNames(podID.Namespace, podID.Name)
	if !exists {
		rndr.Log.Warnf("Unable to get interfaces for pod %v", podID)
		//TODO handle
		//continue
	}

	rndr.Log.Debugf("[DEBUG] Localsid: %v", rndr.IPAM.SidForSFCEndLocalsid(chainEndAddress.IP).String())
	localSID := &vpp_srv6.LocalSID{
		Sid:               rndr.IPAM.SidForSFCEndLocalsid(chainEndAddress.IP).String(),
		InstallationVrfId: rndr.ContivConf.GetRoutingConfig().PodVRFID,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_DX6{
			EndFunction_DX6: &vpp_srv6.LocalSID_EndDX6{
				NextHop:           ipv6AddrAny,
				OutgoingInterface: vppIfName,
			},
		},
	}

	config[models.Key(localSID)] = localSID

	return config, nil
}
