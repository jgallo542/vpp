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
	"strings"

	vpp_l3 "github.com/ligato/vpp-agent/api/models/vpp/l3"
	vpp_srv6 "github.com/ligato/vpp-agent/api/models/vpp/srv6"
	"github.com/ligato/vpp-agent/pkg/models"

	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/sfc/config"
	"github.com/contiv/vpp/plugins/sfc/renderer"
	"github.com/contiv/vpp/plugins/statscollector"
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

	/* FIXME: Rewrite me, only template */
	defaultIfName string
	defaultIfIP   net.IP
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

	config := rndr.renderChain(sfc)
	controller.PutAll(txn, config)

	return nil
}

// UpdateChain informs renderer about a change in the configuration or in the state of a service function chain.
func (rndr *Renderer) UpdateChain(oldSFC, newSFC *renderer.ContivSFC) error {
	rndr.Log.Infof("Update SFC: %v", newSFC)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("update SFC '%s'", newSFC.Name))

	oldConfig := rndr.renderChain(oldSFC)
	newConfig := rndr.renderChain(newSFC)

	controller.DeleteAll(txn, oldConfig)
	controller.PutAll(txn, newConfig)

	return nil
}

// DeleteChain is called for every removed service function chain.
func (rndr *Renderer) DeleteChain(sfc *renderer.ContivSFC) error {

	rndr.Log.Infof("Delete SFC: %v", sfc)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("delete SFC chain '%s'", sfc.Name))

	config := rndr.renderChain(sfc)
	controller.DeleteAll(txn, config)

	return nil
}

// Resync completely replaces the current configuration with the provided full state of service chains.
func (rndr *Renderer) Resync(resyncEv *renderer.ResyncEventData) error {
	txn := rndr.ResyncTxnFactory()

	// resync SFC configuration
	for _, sfc := range resyncEv.Chains {
		config := rndr.renderChain(sfc)
		controller.PutAll(txn, config)
	}

	return nil
}

// Close deallocates resources held by the renderer.
func (rndr *Renderer) Close() error {
	return nil
}

//TODO: Add this functions to tools????
// isIPv6 returns true if the IP address is an IPv6 address, false otherwise.
func isIPv6(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return strings.Contains(ip.String(), ":")
}

func convertIPv4ToIPv6(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}

	if isIPv6(ip) {
		return ip
	}

	return ip.To16()
}

func getHostPrefix(ip net.IP) string {
	if ip == nil {
		return ""
	}

	if isIPv6(ip) {
		return ipv6HostPrefix
	}

	return ipv4HostPrefix
}

func (rndr *Renderer) getTrafficPrefixAddress(sfc *renderer.ContivSFC) (podIP *net.IPNet) {
	podIP = nil

	for _, chain := range sfc.Chain {
		for _, pod := range chain.Pods {
			podIP = rndr.IPAM.GetPodIP(pod.ID)
		}
	}

	return podIP
}

// renderChain renders Contiv SFC to VPP configuration.
func (rndr *Renderer) renderChain(sfc *renderer.ContivSFC) (config controller.KeyValuePairs) {
	config = make(controller.KeyValuePairs)
	//var prevSF *renderer.ServiceFunction

	//todo
	//rndr.Log.Warnf("Unable to get Steering trafix Address for chain %v", sfc)

	rndr.Log.Debugf("[DEBUG]sfc: %v", sfc)

	//rndr.IPAM.SidForSFCEndLocalsid()

	bsid := rndr.IPAM.BsidForSFCPolicy(sfc.Name)
	chainEndAddress := rndr.getTrafficPrefixAddress(sfc)

	steering := &vpp_srv6.Steering{
		Name: "forK8sSFC-" + sfc.Network + "-" + sfc.Name,
		PolicyRef: &vpp_srv6.Steering_PolicyBsid{
			PolicyBsid: bsid.String(),
		},
		Traffic: &vpp_srv6.Steering_L2Traffic_{
			L2Traffic: &vpp_srv6.Steering_L2Traffic{
				InterfaceName: sfc.Chain[0].Pods[0].OutputInterface,

				//PrefixAddress:     chainEndAddress.String(),
				//InstallationVrfId: rndr.ContivConf.GetRoutingConfig().PodVRFID,
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

	ip := convertIPv4ToIPv6(chainEndAddress.IP)
	route := &vpp_l3.Route{
		Type:        vpp_l3.Route_INTER_VRF,
		DstNetwork:  rndr.IPAM.SidForSFCEndLocalsid(ip).String() + ipv6PodSidPrefix,
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

	return config
}

func (rndr *Renderer) getSFInterface(sf *renderer.ServiceFunction, input bool) string {
	if sf.Type != renderer.Pod {
		return "" // TODO: implement external interfaces as well
	}
	if len(sf.Pods) == 0 {
		return ""
	}
	pod := sf.Pods[0] // TODO: handle chains with multiple pod instances per service function?

	podInterface := ""
	if input {
		podInterface = pod.InputInterface
	} else {
		podInterface = pod.OutputInterface
	}

	vppIfName, exists := rndr.IPNet.GetPodCustomIfName(pod.ID.Namespace, pod.ID.Name, podInterface)
	if !exists {
		return ""
	}
	return vppIfName
}
