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

func (rndr *Renderer) firstPodIPAddress(link *renderer.ServiceFunction) (podIP net.IP) {
	for _, pod := range link.Pods {
		podIPNet := rndr.IPAM.GetPodIP(pod.ID)
		if podIPNet == nil || podIPNet.IP == nil {
			continue
		}
		return podIPNet.IP
	}

	return nil
}

// renderChain renders Contiv SFC to VPP configuration.
func (rndr *Renderer) renderChain(sfc *renderer.ContivSFC) (config controller.KeyValuePairs, err error) {
	// TODO support external interaces accros whole renderer
	// TODO support SFC accross multiple nodes
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
	if len(sfc.Chain) == 2 {
		rndr.Log.Warnf("sfc chain %v doesn't have inner links, it has only start and end links", sfc.Name)
	}

	startLink := sfc.Chain[0]
	endLink := sfc.Chain[len(sfc.Chain)-1]

	localStartPods := rndr.localPods(startLink)
	if len(localStartPods) > 1 { // no local start pods = no steering to SFC (-> also no policy)
		bsid := rndr.IPAM.BsidForSFCPolicy(sfc.Name)
		rndr.createSteerings(localStartPods, sfc, bsid, config)
		rndr.createPolicy(sfc, endLink, bsid, config)
	}

	endLinkAddress := rndr.firstPodIPAddress(endLink)
	if endLinkAddress == nil {
		return config, errors.New("can't create sfc chain configuration due to no IP address assigned to end chain link")
	}
	// TODO create inner links (with multinode setup in mind)
	rndr.createInnelLinkLocalsids(config)
	// TODO create end link only if it is local
	rndr.createRouteToPodVrf(endLinkAddress, config)
	rndr.createEndLinkLocalsid(endLinkAddress, config)

	return config, nil
}

func (rndr *Renderer) createInnelLinkLocalsids(config controller.KeyValuePairs) {
	// TODO implement
}

func (rndr *Renderer) createEndLinkLocalsid(endLinkAddress net.IP, config controller.KeyValuePairs) {
	// getting more info about local backend
	podID, found := rndr.IPAM.GetPodFromIP(endLinkAddress)
	if !found {
		rndr.Log.Warnf("Unable to get pod info for backend IP %v", endLinkAddress)
		//TODO handle
		//continue
	}
	vppIfName, _, _, exists := rndr.IPNet.GetPodIfNames(podID.Namespace, podID.Name)
	// TODO use interface defined in sfc chain (make code robust and don't assume that interface in sfc chain is custom, it can be also default)
	if !exists {
		rndr.Log.Warnf("Unable to get interfaces for pod %v", podID)
		//TODO handle
		//continue
	}
	rndr.Log.Debugf("[DEBUG] Localsid: %v", rndr.IPAM.SidForSFCEndLocalsid(endLinkAddress).String())
	localSID := &vpp_srv6.LocalSID{
		Sid:               rndr.IPAM.SidForSFCEndLocalsid(endLinkAddress).String(),
		InstallationVrfId: rndr.ContivConf.GetRoutingConfig().PodVRFID,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_DX6{
			EndFunction_DX6: &vpp_srv6.LocalSID_EndDX6{
				NextHop:           ipv6AddrAny,
				OutgoingInterface: vppIfName,
			},
		},
	}
	config[models.Key(localSID)] = localSID
}

func (rndr *Renderer) createRouteToPodVrf(endLinkAddress net.IP, config controller.KeyValuePairs) {
	route := &vpp_l3.Route{
		Type:        vpp_l3.Route_INTER_VRF,
		DstNetwork:  rndr.IPAM.SidForSFCEndLocalsid(endLinkAddress.To16()).String() + ipv6PodSidPrefix,
		VrfId:       rndr.ContivConf.GetRoutingConfig().MainVRFID,
		ViaVrfId:    rndr.ContivConf.GetRoutingConfig().PodVRFID,
		NextHopAddr: ipv6AddrAny,
	}
	key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	config[key] = route
}

func (rndr *Renderer) createPolicy(sfc *renderer.ContivSFC, endLink *renderer.ServiceFunction, bsid net.IP, config controller.KeyValuePairs) {
	// create Srv6 policy with segment list for each backend (loadbalancing and packet switching part)
	// Fist podIP represent start (steering) function to SRv6
	// Last podIP represent end function to SRv6
	segments := make([]string, 0)
	// add segments for inner links of chain
	for _, chain := range sfc.Chain[1 : len(sfc.Chain)-1] {
		pod := chain.Pods[0] // TODO support multiple pods in inner chain link (multiple loadbalance routes or semething...)
		podIP := rndr.IPAM.GetPodIP(pod.ID)
		segments = append(segments, rndr.IPAM.SidForSFCServiceFunctionLocalsid(sfc.Name, podIP.IP).String())
	}
	// add segment for end link of chain
	podIP := rndr.IPAM.GetPodIP(endLink.Pods[0].ID)
	// TODO support multiple pods in end chain link
	segments = append(segments, rndr.IPAM.SidForSFCEndLocalsid(podIP.IP).String())
	// combine sergments to segment lists
	segmentLists := make([]*vpp_srv6.Policy_SegmentList, 0)
	segmentLists = append(segmentLists,
		&vpp_srv6.Policy_SegmentList{
			Weight:   1,
			Segments: segments,
		})
	// create policy
	policy := &vpp_srv6.Policy{
		InstallationVrfId: rndr.ContivConf.GetRoutingConfig().MainVRFID,
		Bsid:              bsid.String(),
		SegmentLists:      segmentLists,
		SprayBehaviour:    false, // loadbalance packets and not duplicate(spray) it to all segment lists
		SrhEncapsulation:  true,
	}
	config[models.Key(policy)] = policy
}

func (rndr *Renderer) createSteerings(localStartPods []*renderer.PodSF, sfc *renderer.ContivSFC, bsid net.IP, config controller.KeyValuePairs) {
	for _, startPod := range localStartPods {
		steering := &vpp_srv6.Steering{
			Name: fmt.Sprintf("forK8sSFC-%s-from-pod-%s", sfc.Name, startPod.ID.String()),
			PolicyRef: &vpp_srv6.Steering_PolicyBsid{
				PolicyBsid: bsid.String(),
			},
			Traffic: &vpp_srv6.Steering_L2Traffic_{
				L2Traffic: &vpp_srv6.Steering_L2Traffic{
					InterfaceName: startPod.OutputInterface,
				},
			},
		}
		config[models.Key(steering)] = steering
	}
}

func (rndr *Renderer) localPods(sf *renderer.ServiceFunction) []*renderer.PodSF {
	localPods := make([]*renderer.PodSF, 0)
	for _, pod := range sf.Pods {
		if pod.Local {
			localPods = append(localPods, pod)
		}
	}
	return localPods
}
