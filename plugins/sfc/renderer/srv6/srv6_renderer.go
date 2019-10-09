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
	"sort"
	"strings"

	linux_interfaces "github.com/ligato/vpp-agent/api/models/linux/interfaces"
	vpp_interfaces "github.com/ligato/vpp-agent/api/models/vpp/interfaces"

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
	ConfigRetriever  controller.ConfigRetriever
	UpdateTxnFactory func(change string) (txn controller.UpdateOperations)
	ResyncTxnFactory func() (txn controller.ResyncOperations)
	Stats            statscollector.API /* used for exporting the statistics */
}

// ServiceFunctionSelectable is holder for one k8s resource that can be used as ServiceFunction in SFC
// chain (i.e. one pod or one external interface)
type ServiceFunctionSelectable interface {
	Identifier() string
	TypeID() string
	IsLocal() bool
	NodeIdentifier() uint32
	IPNet(ipam ipam.API) *net.IPNet
	InInterface() string
	OutInterface() string
	SidEndLocalSid(ipam ipam.API, podVRF, mainVRF uint32) (net.IP, uint32)
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

const (
	l2DX2Endpoint int = iota
	l3Dx4Endpoint
	l3Dx6Endpoint
)

func (rndr *Renderer) getLinkCustomIfIPNet(sfSelectable ServiceFunctionSelectable, network string) (endLinkCustomIfIPNet *net.IPNet) {
	switch selectable := sfSelectable.(type) {
	case *renderer.PodSF:
		pod := selectable
		return rndr.IPAM.GetPodCustomIfIP(pod.ID, pod.InputInterfaceConfigName, network)
	case *renderer.InterfaceSF:
		extif := selectable
		if ipNet := extif.IPNet(rndr.IPAM); ipNet != nil {
			return ipNet
		}
	default:
		return nil
	}
	return nil
}

// isIPv6 returns true if the IP address is an IPv6 address, false otherwise.
func isIPv6(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return strings.Contains(ip.String(), ":")
}

func (rndr *Renderer) endPointType(sfc *renderer.ContivSFC) int {
	// if end pond IP address is nil, then we use l2endpoint
	endSfSelectable := getEndLinkSfSelectable(sfc)

	rndr.Log.Debugf("endSfSelectable: %v", endSfSelectable)

	endIPNet := rndr.getLinkCustomIfIPNet(endSfSelectable, sfc.Network)
	rndr.Log.Debugf("endIPNet: %v", endIPNet)
	if endIPNet == nil {
		rndr.Log.Debug("Return L2")
		return l2DX2Endpoint
	}

	if isIPv6(endIPNet.IP) {
		rndr.Log.Debug("Return IP6")
		return l3Dx6Endpoint
	}

	rndr.Log.Debug("Return IP4")
	return l3Dx4Endpoint
}

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

	// compute concrete paths from resources selected for SFC chain
	paths, err := rndr.computePaths(sfc)
	if err != nil {
		return config, errors.Wrapf(err, "can't compute paths for SFC chain with name %v", sfc.Name)
	}

	// creating steering and policy (we will install SRv6 components in the same order as packet will go through SFC chain)
	startLocation := remoteLocation
	localStartSfSelectables := rndr.localSfSelectables(sfc.Chain[0])
	if len(localStartSfSelectables) > 0 { // no local start = no steering to SFC (-> also no policy)
		bsid := rndr.IPAM.BsidForSFCPolicy(sfc.Name)
		rndr.createSteerings(localStartSfSelectables, sfc, bsid, config)
		nodeID := localStartSfSelectables[0].NodeIdentifier()
		if err := rndr.createPolicy(paths, sfc, bsid, nodeID, config); err != nil {
			return config, errors.Wrapf(err, "can't create SRv6 policy for SFC chain with name %v", sfc.Name)
		}
		startLocation = mainVRFLocation
	}

	// create inner links and end link for all computed paths
	for _, path := range paths {
		// starting tracking packet location to create correct configuration that enables correct packet routing
		packetLocation := startLocation

		// create inner links and end link for one computed paths
		for i, sfSelectable := range path {
			if sfSelectable.IsLocal() {
				iPNet := sfSelectable.IPNet(rndr.IPAM) // pod IP already allocated (checked in path creation)
				if i == len(path)-1 {                  // end link
					if packetLocation == mainVRFLocation || packetLocation == remoteLocation { // remote packet will arrive in mainVRF -> packet is in mainVRF
						switch sfSelectable := sfSelectable.(type) {
						case *renderer.PodSF:
							rndr.createRouteToPodVrf(rndr.IPAM.SidForSFCEndLocalsid(iPNet.IP.To16()), config)
						case *renderer.InterfaceSF:
							if extIfIPNet := sfSelectable.IPNet(rndr.IPAM); extIfIPNet != nil {
								sid := rndr.IPAM.SidForSFCExternalIfLocalsid(sfSelectable.Identifier(), extIfIPNet.IP.To16())
								rndr.createRouteToPodVrf(sid, config)
							} else {
								sid := rndr.IPAM.SidForSFCExternalIfLocalsid(sfSelectable.Identifier(), nil)
								rndr.createRouteToPodVrf(sid, config)
							}
						}
						packetLocation = podVRFLocation
					}
					if err := rndr.createEndLinkLocalsid(sfc, config, sfSelectable); err != nil {
						return config, errors.Wrapf(err, "can't create end link local sid (%v %v) for sfc chain %v", sfSelectable.TypeID(), sfSelectable.Identifier(), sfc.Name)
					}
				} else { // inner link
					if pod, ok := sfSelectable.(*renderer.PodSF); ok {
						if packetLocation == mainVRFLocation || packetLocation == remoteLocation { // remote packet will arrive in mainVRF -> packet is in mainVRF
							rndr.createRouteToPodVrf(rndr.IPAM.SidForSFCServiceFunctionLocalsid(sfc.Name, iPNet.IP.To16()), config)
							packetLocation = podVRFLocation
						}
						if err := rndr.createInnerLinkLocalsids(sfc, pod, iPNet.IP.To16(), config); err != nil {
							return config, errors.Wrapf(err, "can't create inner link local sid (%v %v) for sfc chain %v", sfSelectable.TypeID(), sfSelectable.Identifier(), sfc.Name)
						}
						if rndr.endPointType(sfc) == l2DX2Endpoint || rndr.endPointType(sfc) == l3Dx4Endpoint {
							// proxy leaving packets check main table instead of pod vrf table // TODO bug?
							// (l2DX2Endpoint -> L2 SR-unware service, l3DX4Endpoint -> L3 IPv4 SR-unware service)
							packetLocation = mainVRFLocation
						}
					} else {
						return nil, errors.Errorf("inner link (%v) is not of pod type", sfSelectable)
					}
				}
			} else {
				if packetLocation == podVRFLocation {
					otherNodeIP, _, err := rndr.IPAM.NodeIPAddress(sfSelectable.NodeIdentifier())
					if err != nil {
						return config, errors.Wrapf(err, "cant create route from pod VRF to main VRF to achieve route "+
							"between local and remote sibling SFC links due to unability to generate node IP address from ID  %v", sfSelectable.NodeIdentifier())
					}
					rndr.createRouteToMainVrf(rndr.IPAM.SidForServiceNodeLocalsid(otherNodeIP), config) // TODO rename SidForServiceNodeLocalsid and related config stuff to reflect usage in SFC
				}
				// NOTE: further routing to intermediate Localsid (Localsid that ends segment that only transports packet to another node) is configured in ipnet package
				// -> no need to add routing out of node here
				packetLocation = remoteLocation
			}

		}
	}

	return config, nil
}

// computePaths takes all resources selected for each SFC link and computes concrete paths for SFC chain
func (rndr *Renderer) computePaths(sfc *renderer.ContivSFC) ([][]ServiceFunctionSelectable, error) {
	// TODO support interfaces for end service functions
	filteredChain := rndr.filterOnlyUsableServiceInstances(sfc)
	rndr.Log.Debugf("creation of SFC chain %v will use only these service function instances: %v",
		sfc.Name, strings.Join(rndr.toStringSlice(filteredChain), ","))

	// path validation
	for _, link := range filteredChain[1:] {
		if link.Type == renderer.Pod {
			if len(link.Pods) == 0 {
				return nil, errors.Errorf("there is no valid path because link %v has no usable "+
					"pods", link)
			}
		} else {
			if len(link.ExternalInterfaces) == 0 {
				return nil, errors.Errorf("there is no valid path because link %v has no usable "+
					"interfaces", link)
			}
		}
	}

	// sorting chain pod/interfaces to get the same path results on each node
	rndr.sortPodsAndInterfaces(filteredChain)

	// get path count
	// Note: SRv6 proxy localsid (pod/interface for inner link in SFC chain) can be used only by one path
	// due to nature of dynamic SRv6 proxy (cache filled by incomming packed and applied to whatever comes
	// out of service -> crossing path here means to possibly applying SRv6 header from cache to packet
	// from different path)
	// That means that path count is limited only by minimum of pods/interfaces selected for each link (
	// pods/interfaces selected for end link can be reused unlimited times in paths)
	pathCount := 1<<31 - 1                                      // more than possible selected pods count
	for _, link := range filteredChain[:len(filteredChain)-1] { // only inner links of original SFC chain
		if len(link.Pods) < pathCount {
			pathCount = len(link.Pods)
		}
	}

	// compute paths
	paths := make([][]ServiceFunctionSelectable, 0)
	for i := 0; i < pathCount; i++ {
		path := make([]ServiceFunctionSelectable, 0)
		for _, link := range filteredChain {
			// Note: modulo will possibly do something only for end link
			if link.Type == renderer.Pod {
				path = append(path, link.Pods[i%len(link.Pods)])
			} else {
				path = append(path, link.ExternalInterfaces[0])
			}
		}
		paths = append(paths, path)
	}

	return paths, nil
}

// sortPodsAndInterfaces makes inplace sort of pods and external interfaces in given chain
func (rndr *Renderer) sortPodsAndInterfaces(chain []*renderer.ServiceFunction) {
	for _, link := range chain {
		// sort pods by podID
		if len(link.Pods) > 1 {
			sort.Slice(link.Pods, func(i, j int) bool {
				return link.Pods[i].ID.String() < link.Pods[j].ID.String()
			})
		}

		// sort external interfaces by NodeID and Interface name
		if len(link.ExternalInterfaces) > 1 {
			sort.Slice(link.ExternalInterfaces, func(i, j int) bool {
				id1 := fmt.Sprintf("%v # %v", link.ExternalInterfaces[i].NodeID,
					link.ExternalInterfaces[i].InterfaceName)
				id2 := fmt.Sprintf("%v # %v", link.ExternalInterfaces[j].NodeID,
					link.ExternalInterfaces[j].InterfaceName)
				return id1 < id2
			})
		}
	}
}

// filterOnlyUsableServiceInstances filters out pods/interfaces that are not usable in SFC chain (
// no IP address,...)
func (rndr *Renderer) filterOnlyUsableServiceInstances(sfc *renderer.ContivSFC) []*renderer.ServiceFunction {
	filteredChain := make([]*renderer.ServiceFunction, 0, len(sfc.Chain)-1)
	for _, link := range sfc.Chain[1:] {
		switch link.Type {
		case renderer.Pod:
			filteredPods := make([]*renderer.PodSF, 0)
			for _, pod := range link.Pods {
				podIPNet := rndr.IPAM.GetPodIP(pod.ID) // needed of SID creation
				if podIPNet == nil || podIPNet.IP == nil {
					rndr.Log.Warnf("excluding pod %v (selected for link %s in SFC chain %v) from SFC "+
						"chain creation because there is no IP address assigned to this pod",
						pod.ID.String(), link.String(), sfc.Name)
					continue
				}

				_, _, err := rndr.IPAM.NodeIPAddress(pod.NodeID) // needed for cross-node SID referencing
				if err != nil {                                  // NOTE: this restriction is actually more strict than needed
					rndr.Log.Warnf("excluding pod %v (selected for link %s in SFC chain %v) from SFC "+
						"chain creation because there is no IP address assigned to the node of this pod "+
						"(nodeID=%v)", pod.ID.String(), link.String(), sfc.Name, pod.NodeID)
					continue
				}
				filteredPods = append(filteredPods, pod)
			}
			filteredChain = append(filteredChain, &renderer.ServiceFunction{
				Type: link.Type,
				Pods: filteredPods,
			})
		case renderer.ExternalInterface: // TODO implement filtering for interfaces
			filteredChain = append(filteredChain, &renderer.ServiceFunction{
				Type:               link.Type,
				ExternalInterfaces: link.ExternalInterfaces,
			})
		}
	}
	return filteredChain
}

func (rndr *Renderer) toStringSlice(chain []*renderer.ServiceFunction) []string {
	result := make([]string, len(chain))
	for i, v := range chain {
		result[i] = v.String()
	}
	return result
}

func (rndr *Renderer) createInnerLinkLocalsids(sfc *renderer.ContivSFC, pod *renderer.PodSF, servicePodIP net.IP, config controller.KeyValuePairs) error {
	localSID := &vpp_srv6.LocalSID{
		Sid:               rndr.IPAM.SidForSFCServiceFunctionLocalsid(sfc.Name, servicePodIP).String(),
		InstallationVrfId: rndr.ContivConf.GetRoutingConfig().PodVRFID,
	}

	switch rndr.endPointType(sfc) {
	case l2DX2Endpoint:
		localSID.EndFunction = &vpp_srv6.LocalSID_EndFunction_AD{EndFunction_AD: &vpp_srv6.LocalSID_EndAD{ // L2 service
			OutgoingInterface: pod.InputInterface,  // outgoing interface for SR-proxy is input interface for service
			IncomingInterface: pod.OutputInterface, // incoming interface for SR-proxy is output interface for service
		}}
	case l3Dx4Endpoint, l3Dx6Endpoint:
		podInputIfIPNet := rndr.IPAM.GetPodCustomIfIP(pod.ID, pod.InputInterfaceConfigName, sfc.Network)
		rndr.Log.Debugf("pod: %v, inputIf: %v, inputIfIP: %v", pod, pod.InputInterfaceConfigName, podInputIfIPNet)
		localSID.EndFunction = &vpp_srv6.LocalSID_EndFunction_AD{EndFunction_AD: &vpp_srv6.LocalSID_EndAD{ // L3 service
			L3ServiceAddress:  podInputIfIPNet.IP.String(),
			OutgoingInterface: pod.InputInterface,  // outgoing interface for SR-proxy is input interface for service
			IncomingInterface: pod.OutputInterface, // incoming interface for SR-proxy is output interface for service
		}}

		if err := rndr.setARPForInputInterface(podInputIfIPNet, config, pod); err != nil {
			return errors.Wrapf(err, "can't set arp for service pod %v", pod.ID)
		}
	}
	config[models.Key(localSID)] = localSID
	return nil
}

func (rndr *Renderer) setARPForInputInterface(ipNet *net.IPNet, config controller.KeyValuePairs, sfSelectable ServiceFunctionSelectable) error {
	var macAddress string
	var err error
	switch sfSelectable := sfSelectable.(type) {
	case *renderer.PodSF:
		pod := sfSelectable
		macAddress, err = rndr.podCustomIFPhysAddress(pod, pod.InputInterfaceConfigName)
		if err != nil {
			return errors.Wrapf(err, "can't retrieve physical(mac) address for custom interface %v on pod %v of sfc chain", pod.InputInterfaceConfigName, pod.ID)
		}
	case *renderer.InterfaceSF:
		extIf := sfSelectable
		macAddress, err = rndr.extIfPhysAddress(extIf)
		if err != nil {
			return errors.Wrapf(err, "can't retrieve physical(mac) address for interface %v of sfc chain", extIf.Identifier())
		}
	}
	arpTable := &vpp_l3.ARPEntry{
		Interface:   sfSelectable.InInterface(),
		IpAddress:   ipNet.IP.String(),
		PhysAddress: macAddress,
		Static:      true,
	}

	config[models.Key(arpTable)] = arpTable
	return nil
}
func (rndr *Renderer) extIfPhysAddress(extIf *renderer.InterfaceSF) (string, error) {
	val := rndr.ConfigRetriever.GetConfig(vpp_interfaces.InterfaceKey(extIf.VppInterfaceName))
	if val == nil {
		return "", errors.Errorf("Unable to get data for interface %v", extIf.InterfaceName)
	}
	vppInterface, ok := val.(*vpp_interfaces.Interface)
	if !ok {
		return "", errors.Errorf("Retrieved data for interface %v have bad type (%+v)", extIf.InterfaceName, val)
	}
	//if vppInterface.PhysAddress == "" {
	//	return "", errors.Errorf("Interface %v has no physical address", vppInterface.Name)
	//}
	return vppInterface.PhysAddress, nil
}

func (rndr *Renderer) podCustomIFPhysAddress(pod *renderer.PodSF, customIFName string) (string, error) {
	_, linuxIfName, exists := rndr.IPNet.GetPodCustomIfNames(pod.ID.Namespace, pod.ID.Name, customIFName)
	if !exists {
		return "", errors.Errorf("Unable to get logical name of custom interface for pod %v", pod.ID)
	}
	val := rndr.ConfigRetriever.GetConfig(linux_interfaces.InterfaceKey(linuxIfName))
	if val == nil {
		return "", errors.Errorf("Unable to get data for custom interface for pod %v", pod.ID)
	}
	linuxInterface, ok := val.(*linux_interfaces.Interface)
	if !ok {
		return "", errors.Errorf("Retrieved data for custom interface for pod %v have bad type (%+v)", pod.ID, val)
	}
	return linuxInterface.PhysAddress, nil
}

func (rndr *Renderer) createEndLinkLocalsid(sfc *renderer.ContivSFC, config controller.KeyValuePairs, endSfSelectable ServiceFunctionSelectable) error {
	sid, installationVrfID := endSfSelectable.SidEndLocalSid(rndr.IPAM, rndr.ContivConf.GetRoutingConfig().PodVRFID, rndr.ContivConf.GetRoutingConfig().MainVRFID)
	localSID := &vpp_srv6.LocalSID{
		Sid:               sid.String(),
		InstallationVrfId: installationVrfID,
	}
	switch rndr.endPointType(sfc) {
	case l2DX2Endpoint:
		localSID.EndFunction = &vpp_srv6.LocalSID_EndFunction_DX2{
			EndFunction_DX2: &vpp_srv6.LocalSID_EndDX2{
				OutgoingInterface: endSfSelectable.InInterface(),
			},
		}
	case l3Dx4Endpoint:
		endIPNet := rndr.getLinkCustomIfIPNet(endSfSelectable, sfc.Network)
		localSID.EndFunction = &vpp_srv6.LocalSID_EndFunction_DX4{
			EndFunction_DX4: &vpp_srv6.LocalSID_EndDX4{
				NextHop:           endIPNet.IP.String(),
				OutgoingInterface: endSfSelectable.InInterface(),
			},
		}
		pod := sfc.Chain[len(sfc.Chain)-1].Pods[0]
		if err := rndr.setARPForInputInterface(endIPNet, config, pod); err != nil {
			return errors.Wrapf(err, "can't set arp for end pod %v", pod.ID)
		}
	case l3Dx6Endpoint:
		endIPNet := rndr.getLinkCustomIfIPNet(endSfSelectable, sfc.Network)
		localSID.EndFunction = &vpp_srv6.LocalSID_EndFunction_DX6{
			EndFunction_DX6: &vpp_srv6.LocalSID_EndDX6{
				NextHop:           endIPNet.IP.String(),
				OutgoingInterface: endSfSelectable.InInterface(),
			},
		}
		if err := rndr.setARPForInputInterface(endIPNet, config, endSfSelectable); err != nil {
			return errors.Wrapf(err, "can't set arp for end %v %v", endSfSelectable.TypeID(), endSfSelectable.Identifier())
		}
	}

	config[models.Key(localSID)] = localSID
	return nil
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

	config[models.Key(route)] = route
}

// createPolicy create Srv6 policy with one segment list for each path in <paths>
func (rndr *Renderer) createPolicy(paths [][]ServiceFunctionSelectable, sfc *renderer.ContivSFC, bsid net.IP,
	thisNodeID uint32, config controller.KeyValuePairs) error {
	// create segment lists
	segmentLists := make([]*vpp_srv6.Policy_SegmentList, 0)
	for _, path := range paths {
		segments := make([]string, 0)
		lastSegmentNode := thisNodeID

		// add segments for inner links of chain
		for i, sfSelectable := range path {
			if lastSegmentNode != sfSelectable.NodeIdentifier() { // move to another node
				nodeIP, _, err := rndr.IPAM.NodeIPAddress(sfSelectable.NodeIdentifier())
				if err != nil {
					return errors.Wrapf(err, "unable to create node-to-node transportation segment due to failure in generatation of node IP address for node id  %v", sfSelectable.NodeIdentifier())
				}
				segments = append(segments, rndr.IPAM.SidForServiceNodeLocalsid(nodeIP.To16()).String())
				lastSegmentNode = sfSelectable.NodeIdentifier()
			}
			if i == len(path)-1 { // end link
				switch sfSelectable.(type) {
				case *renderer.PodSF:
					segments = append(segments, rndr.IPAM.SidForSFCEndLocalsid(sfSelectable.IPNet(rndr.IPAM).IP.To16()).String())
				case *renderer.InterfaceSF:
					if extIfIPNet := sfSelectable.IPNet(rndr.IPAM); extIfIPNet != nil {
						segments = append(segments, rndr.IPAM.SidForSFCExternalIfLocalsid(sfSelectable.Identifier(), extIfIPNet.IP.To16()).String())
					} else {
						segments = append(segments, rndr.IPAM.SidForSFCExternalIfLocalsid(sfSelectable.Identifier(), nil).String())
					}
				}
			} else { // inner link
				segments = append(segments, rndr.IPAM.SidForSFCServiceFunctionLocalsid(sfc.Name, sfSelectable.IPNet(rndr.IPAM).IP.To16()).String())
			}
		}

		// combine segments to segment lists
		segmentLists = append(segmentLists,
			&vpp_srv6.Policy_SegmentList{
				Weight:   1,
				Segments: segments,
			})
	}

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

func (rndr *Renderer) createSteerings(localStartSfSelectables []ServiceFunctionSelectable, sfc *renderer.ContivSFC, bsid net.IP, config controller.KeyValuePairs) {
	switch rndr.endPointType(sfc) {
	case l2DX2Endpoint:
		for _, startSfSelectable := range localStartSfSelectables {
			steering := &vpp_srv6.Steering{
				Name: fmt.Sprintf("forK8sSFC-%s-from-%s-%s", sfc.Name, startSfSelectable.TypeID(), startSfSelectable.Identifier()),
				PolicyRef: &vpp_srv6.Steering_PolicyBsid{
					PolicyBsid: bsid.String(),
				},
				Traffic: &vpp_srv6.Steering_L2Traffic_{
					L2Traffic: &vpp_srv6.Steering_L2Traffic{
						InterfaceName: startSfSelectable.OutInterface(),
					},
				},
			}
			rndr.Log.Debugf("[DEBUG] l2 steering: %v", steering)
			config[models.Key(steering)] = steering
		}
	case l3Dx6Endpoint, l3Dx4Endpoint:
		endSfSelectable := getEndLinkSfSelectable(sfc)
		endIPNet := rndr.getLinkCustomIfIPNet(endSfSelectable, sfc.Network)
		steering := &vpp_srv6.Steering{
			Name: fmt.Sprintf("forK8sSFC-%s", sfc.Name),
			PolicyRef: &vpp_srv6.Steering_PolicyBsid{
				PolicyBsid: bsid.String(),
			},
			Traffic: &vpp_srv6.Steering_L3Traffic_{
				L3Traffic: &vpp_srv6.Steering_L3Traffic{
					InstallationVrfId: rndr.ContivConf.GetRoutingConfig().PodVRFID,
					PrefixAddress:     endIPNet.String(),
				},
			},
		}
		config[models.Key(steering)] = steering
	}
}

func (rndr *Renderer) localSfSelectables(sf *renderer.ServiceFunction) []ServiceFunctionSelectable {
	localSfSelectables := make([]ServiceFunctionSelectable, 0)
	for _, pod := range sf.Pods {
		if pod.Local {
			localSfSelectables = append(localSfSelectables, pod)
		}
	}
	for _, extif := range sf.ExternalInterfaces {
		if extif.Local {
			localSfSelectables = append(localSfSelectables, extif)
		}
	}
	return localSfSelectables
}

func getEndLinkSfSelectable(sfc *renderer.ContivSFC) ServiceFunctionSelectable {
	if sfc.Chain[len(sfc.Chain)-1].Type == renderer.Pod {
		return sfc.Chain[len(sfc.Chain)-1].Pods[0]
	} else {
		return sfc.Chain[len(sfc.Chain)-1].ExternalInterfaces[0]
	}
}
