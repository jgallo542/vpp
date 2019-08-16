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
func (rndr *Renderer) Init() error {
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

// locations for packet that is travelling SFC chain
const (
	remoteLocation int = iota
	podVRFLocation
	mainVRFLocation
)

// renderChain renders Contiv SFC to VPP configuration.
func (rndr *Renderer) renderChain(sfc *renderer.ContivSFC) (config controller.KeyValuePairs, err error) {
	// TODO support external interfaces across whole renderer
	// TODO remove all debug logging later
	rndr.Log.Debugf("[DEBUG]sfc: %v", sfc)

	// SFC configuration correctness checks
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

	// creating steering and policy (we will install SRv6 components in the same order as packet will go through SFC chain)
	packetLocation := remoteLocation // tracking packet location to create correct configuration that enables correct packet routing
	localStartPods := rndr.localPods(sfc.Chain[0])
	if len(localStartPods) > 0 { // no local start pods = no steering to SFC (-> also no policy)
		bsid := rndr.IPAM.BsidForSFCPolicy(sfc.Name)
		rndr.createSteerings(localStartPods, sfc, bsid, config)
		if err := rndr.createPolicy(sfc, bsid, localStartPods[0].NodeID, config); err != nil {
			return config, errors.Wrapf(err, "can't create SRv6 policy for SFC chain with name %v", sfc.Name)
		}
		packetLocation = mainVRFLocation
	}

	// create inner links and end link
	for i, link := range sfc.Chain[1:len(sfc.Chain)] {
		pod := link.Pods[0] // TODO support multiple pods in inner/end chain link (multiple loadbalance routes or something...)
		if pod.Local {
			podIPNet := rndr.IPAM.GetPodIP(pod.ID)
			if podIPNet == nil || podIPNet.IP == nil {
				return config, errors.Errorf("excluding link %s from SFC chain(localsid creation) because there is no IP address for pod %s", link.String(), pod.ID.String())
			}
			if i == len(sfc.Chain)-2 { // end link
				if packetLocation == mainVRFLocation || packetLocation == remoteLocation { // remote packet will arrive in mainVRF -> packet is in mainVRF
					rndr.createRouteToPodVrf(rndr.IPAM.SidForSFCEndLocalsid(podIPNet.IP.To16()), config)
					packetLocation = podVRFLocation
				}
				rndr.createEndLinkLocalsid(podIPNet.IP.To16(), config, pod.InputInterface)
			} else { // inner link
				if packetLocation == mainVRFLocation || packetLocation == remoteLocation { // remote packet will arrive in mainVRF -> packet is in mainVRF
					rndr.createRouteToPodVrf(rndr.IPAM.SidForSFCServiceFunctionLocalsid(sfc.Name, podIPNet.IP.To16()), config)
					packetLocation = podVRFLocation
				}
				rndr.createInnelLinkLocalsids(sfc.Name, pod, podIPNet.IP.To16(), config)
			}
		} else {
			if packetLocation == podVRFLocation {
				otherNodeIP, _, err := rndr.IPAM.NodeIPAddress(pod.NodeID)
				if err != nil {
					return config, errors.Wrapf(err, "cant create route from pod VRF to main VRF to achieve route "+
						"between local and remote sibling SFC links due to unability to generate node IP address from pod ID  %v", pod.NodeID)
				}
				rndr.createRouteToMainVrf(rndr.IPAM.SidForServiceNodeLocalsid(otherNodeIP), config) // TODO rename SidForServiceNodeLocalsid and related config stuff to reflect usage in SFC
			}
			// NOTE: further routing to intermediate Localsid (Localsid that ends segment that only transports packet to another node) is configured in ipnet package
			// -> no need to add routing out of node here
			packetLocation = remoteLocation
		}
	}

	return config, nil
}

func (rndr *Renderer) createInnelLinkLocalsids(sfcName string, pod *renderer.PodSF, servicePodIP net.IP, config controller.KeyValuePairs) {
	localSID := &vpp_srv6.LocalSID{
		Sid:               rndr.IPAM.SidForSFCServiceFunctionLocalsid(sfcName, servicePodIP).String(),
		InstallationVrfId: rndr.ContivConf.GetRoutingConfig().PodVRFID,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_AD{EndFunction_AD: &vpp_srv6.LocalSID_EndAD{ // L2 service
			L3ServiceAddress:  "2001:0:0:1::7",     //"bd:1::d",
			OutgoingInterface: pod.InputInterface,  // outgoing interface for SR-proxy is input interface for service
			IncomingInterface: pod.OutputInterface, // incoming interface for SR-proxy is output interface for service
		}},
	}
	config[models.Key(localSID)] = localSID
}

func (rndr *Renderer) createEndLinkLocalsid(endLinkAddress net.IP, config controller.KeyValuePairs, outputIfName string) {
	rndr.Log.Debugf("[DEBUG] Localsid: %v", rndr.IPAM.SidForSFCEndLocalsid(endLinkAddress).String())
	localSID := &vpp_srv6.LocalSID{
		Sid:               rndr.IPAM.SidForSFCEndLocalsid(endLinkAddress).String(),
		InstallationVrfId: rndr.ContivConf.GetRoutingConfig().PodVRFID,
		//TODO Implement support for different type of dx
		EndFunction: &vpp_srv6.LocalSID_EndFunction_DX6{
			EndFunction_DX6: &vpp_srv6.LocalSID_EndDX6{
				NextHop:           "2001:0:0:1::7",
				OutgoingInterface: outputIfName,
			},
		},
		//EndFunction: &vpp_srv6.LocalSID_EndFunction_DX2{
		//	EndFunction_DX2: &vpp_srv6.LocalSID_EndDX2{
		//		OutgoingInterface: outputIfName,
		//	},
		//},
	}
	config[models.Key(localSID)] = localSID
}

func (rndr *Renderer) createRouteToPodVrf(steeredIP net.IP, config controller.KeyValuePairs) {
	rndr.createRouteBetweenVrfTables(rndr.ContivConf.GetRoutingConfig().MainVRFID, rndr.ContivConf.GetRoutingConfig().PodVRFID, steeredIP, config)
}

func (rndr *Renderer) createRouteToMainVrf(steeredIP net.IP, config controller.KeyValuePairs) {
	rndr.createRouteBetweenVrfTables(rndr.ContivConf.GetRoutingConfig().PodVRFID, rndr.ContivConf.GetRoutingConfig().MainVRFID, steeredIP, config)
}

func (rndr *Renderer) createRouteBetweenVrfTables(fromVrf, toVrf uint32, steeredIP net.IP, config controller.KeyValuePairs) {
	route := &vpp_l3.Route{
		Type:        vpp_l3.Route_INTER_VRF,
		DstNetwork:  steeredIP.String() + ipv6PodSidPrefix,
		VrfId:       fromVrf,
		ViaVrfId:    toVrf,
		NextHopAddr: ipv6AddrAny,
	}
	key := vpp_l3.RouteKey(route.VrfId, route.DstNetwork, route.NextHopAddr)
	config[key] = route
}

func (rndr *Renderer) createPolicy(sfc *renderer.ContivSFC, bsid net.IP, thisNodeID uint32, config controller.KeyValuePairs) error {
	// create Srv6 policy with segment list for each backend (loadbalancing and packet switching part)
	// Fist podIP represent start (steering) function to SRv6
	// Last podIP represent end function to SRv6
	segments := make([]string, 0)
	lastSegmentNode := thisNodeID

	// add segments for inner links of chain
	for i, link := range sfc.Chain[1:len(sfc.Chain)] {
		pod := link.Pods[0] // TODO support multiple pods in inner/end chain link (multiple loadbalance routes or something...)
		podIPNet := rndr.IPAM.GetPodIP(pod.ID)
		if podIPNet == nil || podIPNet.IP == nil {
			return errors.Errorf("excluding link %s from SFC chain(policy creation) because there is no IP address for pod %s", link.String(), pod.ID.String())
		}
		if lastSegmentNode != pod.NodeID { // move to another node
			nodeIP, _, err := rndr.IPAM.NodeIPAddress(pod.NodeID)
			if err != nil {
				return errors.Wrapf(err, "unable to create node-to-node transportation segment due to failure in generatation of node IP address for node id  %v", pod.NodeID)
			}
			segments = append(segments, rndr.IPAM.SidForServiceNodeLocalsid(nodeIP).String())
			lastSegmentNode = pod.NodeID
		}
		if i == len(sfc.Chain)-2 { // end link
			segments = append(segments, rndr.IPAM.SidForSFCEndLocalsid(podIPNet.IP.To16()).String())
		} else { // inner link
			segments = append(segments, rndr.IPAM.SidForSFCServiceFunctionLocalsid(sfc.Name, podIPNet.IP.To16()).String())
		}
	}

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
	return nil
}

func (rndr *Renderer) createSteerings(localStartPods []*renderer.PodSF, sfc *renderer.ContivSFC, bsid net.IP, config controller.KeyValuePairs) {
	//for _, startPod := range localStartPods {
	//	steering := &vpp_srv6.Steering{
	//		Name: fmt.Sprintf("forK8sSFC-%s-from-pod-%s", sfc.Name, startPod.ID.String()),
	//		PolicyRef: &vpp_srv6.Steering_PolicyBsid{
	//			PolicyBsid: bsid.String(),
	//		},
	//		Traffic: &vpp_srv6.Steering_L2Traffic_{
	//			L2Traffic: &vpp_srv6.Steering_L2Traffic{
	//				InterfaceName: startPod.OutputInterface,
	//			},
	//		},
	//	}
	//	config[models.Key(steering)] = steering
	//}

	// TODO try computation when using default network (in pod creation yaml)
	//endLinkPod := sfc.Chain[len(sfc.Chain)-1].Pods[0]
	//rndr.Log.Debugf("[DEBUG] steering: end pod custom if = %v or %v", endLinkPod.InputInterface, endLinkPod.OutputInterface)
	//rndr.Log.Debugf("[DEBUG] steering: end pod custom if IP = %v or %v", rndr.IPAM.GetPodCustomIfIP(endLinkPod.ID, endLinkPod.InputInterface, sfc.Network),
	//	rndr.IPAM.GetPodCustomIfIP(endLinkPod.ID, endLinkPod.OutputInterface, sfc.Network))
	//endLinkCustomIfIPNet := rndr.IPAM.GetPodCustomIfIP(endLinkPod.ID, endLinkPod.InputInterface, sfc.Network)

	steering := &vpp_srv6.Steering{
		Name: fmt.Sprintf("forK8sSFC-%s", sfc.Name),
		PolicyRef: &vpp_srv6.Steering_PolicyBsid{
			PolicyBsid: bsid.String(),
		},
		Traffic: &vpp_srv6.Steering_L3Traffic_{
			L3Traffic: &vpp_srv6.Steering_L3Traffic{
				InstallationVrfId: rndr.ContivConf.GetRoutingConfig().PodVRFID,
				PrefixAddress:     "2001:0:0:1::7/128", //endLinkCustomIfIPNet.IP.String() + getHostPrefix(endLinkCustomIfIPNet.IP),
			},
		},
	}
	config[models.Key(steering)] = steering
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
