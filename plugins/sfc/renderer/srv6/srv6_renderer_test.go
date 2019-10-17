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

package srv6_test

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"testing"

	sfcmodel "github.com/contiv/vpp/plugins/crd/handler/servicefunctionchain/model"
	"github.com/contiv/vpp/plugins/ipam/ipalloc"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/podmanager"

	"github.com/contiv/vpp/mock/configRetriever"
	. "github.com/contiv/vpp/mock/datasync"
	. "github.com/contiv/vpp/mock/ipnet"
	"github.com/contiv/vpp/mock/localclient"
	. "github.com/contiv/vpp/mock/nodesync"
	. "github.com/contiv/vpp/mock/podmanager"
	. "github.com/contiv/vpp/mock/servicelabel"
	"github.com/contiv/vpp/mock/vppagent"
	"github.com/contiv/vpp/mock/vppagent/handler"
	"github.com/contiv/vpp/plugins/contivconf"
	contivconf_config "github.com/contiv/vpp/plugins/contivconf/config"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/sfc/processor"
	"github.com/contiv/vpp/plugins/sfc/renderer"
	"github.com/contiv/vpp/plugins/sfc/renderer/srv6"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	linux_interfaces "github.com/ligato/vpp-agent/api/models/linux/interfaces"
	vpp_srv6 "github.com/ligato/vpp-agent/api/models/vpp/srv6"
	scheduler "github.com/ligato/vpp-agent/plugins/kvscheduler/api"

	. "github.com/onsi/gomega"
)

const (
	// MasterLabel is node label of master
	MasterLabel = "master"
	// MasterID is node ID of master
	MasterID = uint32(1)
	// WorkerLabel is node label of worker
	WorkerLabel = "worker"
	// WorkerID is node ID of worker
	WorkerID = uint32(2)

	// Namespace1 is first testing namespace
	Namespace1 = "default"
	// Namespace2 is second testing namespace
	Namespace2 = "another-ns"

	// MainVrfID is id of main vrf table
	MainVrfID = 0
	// PodVrfID is id of pod vrf table
	PodVrfID = 1

	podSelectorKey       = "sf"
	podSelectorValPrefix = "sf"

	pod1InputInterfaceName  = "pod1-tap1"
	pod2InputInterfaceName  = "pod2-tap1"
	pod2OutputInterfaceName = "pod2-tap2"
	pod3InputInterfaceName  = "pod3-tap1"
	pod3OutputInterfaceName = "pod3-tap2"
	pod4InputInterfaceName  = "pod4-tap1"

	pod1InputIfIP  = "2001::1:0:0:2:1"
	pod2InputIfIP  = "2001::1:0:0:2:2"
	pod2OutputIfIP = "2001::1:0:0:2:3"
	pod3InputIfIP  = "2001::1:0:0:2:4"
	pod3OutputIfIP = "2001::1:0:0:2:5"
	pod4InputIfIP  = "2001::1:0:0:2:6"

	pod1InputIfMAC  = "00:00:00:00:01:01"
	pod2InputIfMAC  = "00:00:00:00:02:01"
	pod2OutputIfMAC = "00:00:00:00:02:02"
	pod3InputIfMAC  = "00:00:00:00:03:01"
	pod3OutputIfMAC = "00:00:00:00:03:02"
	pod4InputIfMAC  = "00:00:00:00:04:01"
)

var (
	// master
	nodeIPNetString        = "2005:0:0:0:0:0:16:10/112"
	nodeIP, nodeNetwork, _ = net.ParseCIDR(nodeIPNetString)
	nodeIPNet              = &net.IPNet{IP: nodeIP, Mask: nodeNetwork.Mask}

	mgmtIP = net.ParseIP("2002:0:0:0:0:0:1:1")

	ipV6Conf = &contivconf_config.Config{
		InterfaceConfig: contivconf_config.InterfaceConfig{
			UseTAPInterfaces:    true,
			TAPInterfaceVersion: 2,
		},
		RoutingConfig: contivconf_config.RoutingConfig{
			NodeToNodeTransport:               "srv6",
			UseSRv6ForServiceFunctionChaining: true,
		},
		IPAMConfig: contivconf_config.IPAMConfig{
			NodeInterconnectDHCP:          false,
			NodeInterconnectCIDR:          "e10:f00d::/90",
			PodSubnetCIDR:                 "2001::/48",
			PodSubnetOneNodePrefixLen:     64,
			VPPHostSubnetCIDR:             "2002::/64",
			VPPHostSubnetOneNodePrefixLen: 112,
			VxlanCIDR:                     "2005::/112",
			ServiceCIDR:                   "2096::/110",
			SRv6: contivconf_config.SRv6Config{
				ServicePolicyBSIDSubnetCIDR:            "8fff::/16",
				ServicePodLocalSIDSubnetCIDR:           "9300::/16",
				ServiceHostLocalSIDSubnetCIDR:          "9300::/16",
				ServiceNodeLocalSIDSubnetCIDR:          "9000::/16",
				NodeToNodePodLocalSIDSubnetCIDR:        "9501::/16",
				NodeToNodeHostLocalSIDSubnetCIDR:       "9500::/16",
				NodeToNodePodPolicySIDSubnetCIDR:       "8501::/16",
				NodeToNodeHostPolicySIDSubnetCIDR:      "8500::/16",
				SFCPolicyBSIDSubnetCIDR:                "8eee::/16",
				SFCServiceFunctionSIDSubnetCIDR:        "9600::/16",
				SFCEndLocalSIDSubnetCIDR:               "9310::/16",
				SFCIDLengthUsedInSidForServiceFunction: 16,
			},
		},
	}
)

type Fixture struct {
	SFCProcessor     *processor.SFCProcessor
	renderer         *srv6.Renderer
	Log              logging.Logger
	IPAM             *ipam.IPAM
	IPNet            *MockIPNet
	ContivConf       *contivconf.ContivConf
	Datasync         *MockDataSync
	ServiceLabel     *MockServiceLabel
	NodeSync         *MockNodeSync
	PodManager       *MockPodManager
	Srv6Handler      *handler.SRv6MockHandler
	RouteHandler     *handler.RouteMockHandler
	ConfigRetriever  *configRetriever.MockConfigRetriever
	InterfaceHandler *handler.InterfaceMockHandler
	TxnTracker       *localclient.TxnTracker
	Txn              *Txn
}

type sfcConfig struct {
	Policy    *vpp_srv6.Policy
	Steering  *vpp_srv6.Steering
	Localsids []*vpp_srv6.LocalSID
}

// TestOneNodeChain
func TestOneNodeChain(t *testing.T) {
	RegisterTestingT(t)

	fixture := newFixture("TestOneNodeChain")

	sfc, config := getOneNodePodToPodChain(fixture)

	assertConfig(false, config, fixture)

	addSFC(sfc, fixture)

	assertConfig(true, config, fixture)
}

func assertConfig(exists bool, c *sfcConfig, fixture *Fixture) {

	if c.Localsids != nil {
		for _, localsid := range c.Localsids {
			if exists {
				Expect(fixture.Srv6Handler.LocalSids).To(ContainElement(localsid))
			} else {
				Expect(fixture.Srv6Handler.LocalSids).ToNot(ContainElement(localsid))
			}
		}
	}

	if c.Policy != nil {
		Expect(hasPolicy(c.Policy, fixture.Srv6Handler.Policies)).To(Equal(exists))
	}

	if exists {
		Expect(fixture.Srv6Handler.Steerings).To(ContainElement(c.Steering))
	} else {
		Expect(fixture.Srv6Handler.Steerings).ToNot(ContainElement(c.Steering))
	}
}

func getOneNodePodToPodChain(fixture *Fixture) (*renderer.ContivSFC, *sfcConfig) {

	// create SFC configuration
	pod1ID := podmodel.ID{
		Name:      "pod1",
		Namespace: "default",
	}

	pod1 := &renderer.PodSF{
		ID:             pod1ID,
		NodeID:         1,
		Local:          true,
		InputInterface: interfaceNames(pod1InputInterfaceName, pod1InputInterfaceName),
	}
	sf1 := &renderer.ServiceFunction{
		Type: renderer.Pod,
		Pods: []*renderer.PodSF{pod1},
	}

	pod2ID := podmodel.ID{
		Name:      "pod2",
		Namespace: "default",
	}
	pod2 := &renderer.PodSF{
		ID:              pod2ID,
		NodeID:          1,
		Local:           true,
		InputInterface:  interfaceNames(pod2InputInterfaceName, pod2InputInterfaceName),
		OutputInterface: interfaceNames(pod2OutputInterfaceName, pod2OutputInterfaceName),
	}
	sf2 := &renderer.ServiceFunction{
		Type: renderer.Pod,
		Pods: []*renderer.PodSF{pod2},
	}

	pod3ID := podmodel.ID{
		Name:      "pod3",
		Namespace: "default",
	}
	pod3 := &renderer.PodSF{
		ID:              pod3ID,
		NodeID:          1,
		Local:           true,
		InputInterface:  interfaceNames(pod3InputInterfaceName, pod3InputInterfaceName),
		OutputInterface: interfaceNames(pod3OutputInterfaceName, pod3OutputInterfaceName),
	}
	sf3 := &renderer.ServiceFunction{
		Type: renderer.Pod,
		Pods: []*renderer.PodSF{pod3},
	}

	pod4ID := podmodel.ID{
		Name:      "pod4",
		Namespace: "default",
	}
	pod4 := &renderer.PodSF{
		ID:             pod4ID,
		NodeID:         1,
		Local:          true,
		InputInterface: interfaceNames(pod4InputInterfaceName, pod4InputInterfaceName),
	}
	sf4 := &renderer.ServiceFunction{
		Type: renderer.Pod,
		Pods: []*renderer.PodSF{pod4},
	}

	sfc := &renderer.ContivSFC{
		Name:  "chain",
		Chain: []*renderer.ServiceFunction{sf1, sf2, sf3, sf4},
	}

	// spawn the pods
	addPod(pod1ID, true, 0, fixture)
	addPodCustomIf(pod1ID, pod1InputInterfaceName, pod1InputIfIP, pod1InputIfMAC, fixture)

	pod2IP := addPod(pod2ID, true, 1, fixture)
	addPodCustomIf(pod2ID, pod2InputInterfaceName, pod2InputIfIP, pod2InputIfMAC, fixture)
	addPodCustomIf(pod2ID, pod2OutputInterfaceName, pod2OutputIfIP, pod2OutputIfMAC, fixture)

	pod3IP := addPod(pod3ID, true, 2, fixture)
	addPodCustomIf(pod3ID, pod3InputInterfaceName, pod3InputIfIP, pod3InputIfMAC, fixture)
	addPodCustomIf(pod3ID, pod3OutputInterfaceName, pod3OutputIfIP, pod3OutputIfMAC, fixture)

	pod4IP := addPod(pod4ID, true, 3, fixture)
	addPodCustomIf(pod4ID, pod4InputInterfaceName, pod4InputIfIP, pod4InputIfMAC, fixture)

	// expected configuration
	localSID1 := &vpp_srv6.LocalSID{
		Sid:               fixture.IPAM.SidForSFCServiceFunctionLocalsid(sfc.Name, pod2IP.To16()).String(),
		InstallationVrfId: PodVrfID,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_AD{EndFunction_AD: &vpp_srv6.LocalSID_EndAD{
			L3ServiceAddress:  pod2InputIfIP,
			OutgoingInterface: pod2InputInterfaceName,
			IncomingInterface: pod2OutputInterfaceName,
		}},
	}
	localSID2 := &vpp_srv6.LocalSID{
		Sid:               fixture.IPAM.SidForSFCServiceFunctionLocalsid(sfc.Name, pod3IP.To16()).String(),
		InstallationVrfId: PodVrfID,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_AD{EndFunction_AD: &vpp_srv6.LocalSID_EndAD{
			L3ServiceAddress:  pod3InputIfIP,
			OutgoingInterface: pod3InputInterfaceName,
			IncomingInterface: pod3OutputInterfaceName,
		}},
	}
	localSID3 := &vpp_srv6.LocalSID{
		Sid:               fixture.IPAM.SidForSFCEndLocalsid(pod4IP.To16()).String(),
		InstallationVrfId: PodVrfID,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_DX6{
			EndFunction_DX6: &vpp_srv6.LocalSID_EndDX6{
				NextHop:           pod4InputIfIP,
				OutgoingInterface: pod4InputInterfaceName,
			},
		},
	}

	segments := make([]string, 0)
	segments = append(segments, localSID1.Sid, localSID2.Sid, localSID3.Sid)
	segmentLists := make([]*vpp_srv6.Policy_SegmentList, 0)
	segmentLists = append(segmentLists,
		&vpp_srv6.Policy_SegmentList{
			Weight:   1,
			Segments: segments,
		})
	bsid := fixture.IPAM.BsidForSFCPolicy(sfc.Name)
	policy := &vpp_srv6.Policy{
		InstallationVrfId: MainVrfID,
		Bsid:              bsid.String(),
		SegmentLists:      segmentLists,
		SprayBehaviour:    false,
		SrhEncapsulation:  true,
	}

	endIPNet := net.IPNet{IP: net.ParseIP(pod4InputIfIP), Mask: net.CIDRMask(128, 128)}
	steering := &vpp_srv6.Steering{
		Name: fmt.Sprintf("forK8sSFC-%s", sfc.Name),
		PolicyRef: &vpp_srv6.Steering_PolicyBsid{
			PolicyBsid: bsid.String(),
		},
		Traffic: &vpp_srv6.Steering_L3Traffic_{
			L3Traffic: &vpp_srv6.Steering_L3Traffic{
				InstallationVrfId: PodVrfID,
				PrefixAddress:     endIPNet.String(),
			},
		},
	}

	expectedConfig := &sfcConfig{
		Policy:   policy,
		Steering: steering,
		Localsids: []*vpp_srv6.LocalSID{
			localSID1,
			localSID2,
			localSID3,
		},
	}

	return sfc, expectedConfig
}

func newFixture(testName string) *Fixture {
	fixture := &Fixture{}

	// Logger
	fixture.Log = logrus.DefaultLogger()
	fixture.Log.SetLevel(logging.DebugLevel)
	fixture.Log.Debug(testName)

	// Tracker of ongoing transaction
	fixture.Txn = &Txn{}

	// Srv6 Handler
	fixture.Srv6Handler = handler.NewSRv6Mock(fixture.Log)

	// Route Handler
	fixture.RouteHandler = handler.NewRouteMock(fixture.Log)

	// Interface Handler
	fixture.InterfaceHandler = handler.NewInterfaceMock(fixture.Log)

	// TxnTracker
	vppAgentMock := vppagent.NewMockVPPAgent(fixture.Srv6Handler, fixture.RouteHandler, fixture.InterfaceHandler)
	fixture.TxnTracker = localclient.NewTxnTracker(vppAgentMock.ApplyTxn)

	// Datasync
	fixture.Datasync = NewMockDataSync()

	// mock service label
	fixture.ServiceLabel = NewMockServiceLabel()
	fixture.ServiceLabel.SetAgentLabel(MasterLabel)

	// contivConf plugin
	fixture.ContivConf = &contivconf.ContivConf{
		Deps: contivconf.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("contivconf"),
			},
			ServiceLabel: fixture.ServiceLabel,
			UnitTestDeps: &contivconf.UnitTestDeps{
				Config: ipV6Conf,
			},
		},
	}

	Expect(fixture.ContivConf.Init()).To(BeNil())
	resyncEv, _ := fixture.Datasync.ResyncEvent()
	Expect(fixture.ContivConf.Resync(resyncEv, resyncEv.KubeState, 1, nil)).To(BeNil())

	fixture.NodeSync = NewMockNodeSync(MasterLabel)
	fixture.NodeSync.UpdateNode(&nodesync.Node{
		Name:            MasterLabel,
		ID:              MasterID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: nodeIP, Network: nodeIPNet}},
		MgmtIPAddresses: []net.IP{mgmtIP},
	})
	Expect(fixture.NodeSync.GetNodeID()).To(BeEquivalentTo(1))

	// IPAM real plugin
	fixture.IPAM = &ipam.IPAM{
		Deps: ipam.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("IPAM"),
			},
			NodeSync:   fixture.NodeSync,
			ContivConf: fixture.ContivConf,
		},
	}
	Expect(fixture.IPAM.Init()).ShouldNot(HaveOccurred())
	Expect(fixture.IPAM.Resync(resyncEv, resyncEv.KubeState, 1, nil)).To(BeNil())

	// podmanager
	fixture.PodManager = NewMockPodManager()

	// SFC Processor
	fixture.SFCProcessor = &processor.SFCProcessor{
		Deps: processor.Deps{
			Log:          fixture.Log,
			ServiceLabel: fixture.ServiceLabel,
			ContivConf:   fixture.ContivConf,
			NodeSync:     fixture.NodeSync,
			PodManager:   fixture.PodManager,
			IPAM:         fixture.IPAM,
			IPNet:        fixture.IPNet,
		},
	}
	fixture.SFCProcessor.Init()

	// Config Retriever
	fixture.ConfigRetriever = configRetriever.NewMockConfigRetriever()

	// SRV6 Renderer
	fixture.renderer = &srv6.Renderer{
		Deps: srv6.Deps{
			Log:              fixture.Log,
			ContivConf:       fixture.ContivConf,
			IPAM:             fixture.IPAM,
			IPNet:            fixture.IPNet,
			ConfigRetriever:  fixture.ConfigRetriever,
			ResyncTxnFactory: fixture.Txn.ResyncFactory(fixture.TxnTracker),
			UpdateTxnFactory: fixture.Txn.UpdateFactory(fixture.TxnTracker),
		},
	}

	Expect(fixture.renderer.Init()).To(BeNil())
	Expect(fixture.SFCProcessor.RegisterRenderer(fixture.renderer)).To(BeNil())

	return fixture
}

// Txn is mock of ongoing transaction
type Txn struct {
	isResync bool
	vppTxn   controller.Transaction
}

// Commit is mock commit function for ongoing mock transaction
func (t *Txn) Commit() error {
	if t.vppTxn == nil {
		return nil
	}
	ctx := context.Background()
	if t.isResync {
		ctx = scheduler.WithResync(ctx, scheduler.FullResync, true)
	}
	_, err := t.vppTxn.Commit(ctx)
	t.vppTxn = nil
	return err
}

// ResyncFactory creates factory for mock transaction resync operations
func (t *Txn) ResyncFactory(txnTracker *localclient.TxnTracker) func() controller.ResyncOperations {
	return func() controller.ResyncOperations {
		if t.vppTxn != nil {
			return t.vppTxn
		}
		t.vppTxn = txnTracker.NewControllerTxn(true)
		t.isResync = true
		return t.vppTxn
	}
}

// UpdateFactory creates factory for mock transaction update operations
func (t *Txn) UpdateFactory(txnTracker *localclient.TxnTracker) func(change string) controller.UpdateOperations {
	return func(change string) controller.UpdateOperations {
		if t.vppTxn != nil {
			return t.vppTxn
		}
		t.vppTxn = txnTracker.NewControllerTxn(false)
		t.isResync = false
		return t.vppTxn
	}
}

func getExpectedConfig(sfc *renderer.ContivSFC, fixture *Fixture) {
}

func addSFC(sfc *renderer.ContivSFC, fixture *Fixture) {
	newSFC := &sfcmodel.ServiceFunctionChain{
		Name:    sfc.Name,
		Network: sfc.Network,
		Chain:   make([]*sfcmodel.ServiceFunctionChain_ServiceFunction, 0),
	}
	for i, link := range sfc.Chain {
		newSF := &sfcmodel.ServiceFunctionChain_ServiceFunction{
			Name: "SF" + strconv.Itoa(i),
		}
		switch link.Type {
		case renderer.Pod:
			newSF.Type = sfcmodel.ServiceFunctionChain_ServiceFunction_Pod
			newSF.PodSelector = map[string]string{podSelectorKey: podSelectorValPrefix + strconv.Itoa(i)}
			newSF.InputInterface = link.Pods[0].InputInterface.CRDName
			newSF.OutputInterface = link.Pods[0].OutputInterface.CRDName
		case renderer.ExternalInterface:
			newSF.Type = sfcmodel.ServiceFunctionChain_ServiceFunction_ExternalInterface
			newSF.Interface = link.ExternalInterfaces[0].InterfaceName
		}
		newSFC.Chain = append(newSFC.Chain, newSF)
	}
	ev := &controller.KubeStateChange{
		Key:      sfcmodel.Key(sfc.Name),
		Resource: sfcmodel.Keyword,
		NewValue: newSFC,
	}

	Expect(fixture.SFCProcessor.Update(ev)).To(BeNil())
	Expect(fixture.Txn.Commit()).To(BeNil())
}

func addPodCustomIf(podID podmodel.ID, ifName string, ip, mac string, fixture *Fixture) {
	newIf := &ipalloc.CustomIPAllocation{
		PodName:      podID.Name,
		PodNamespace: podID.Namespace,
		CustomInterfaces: []*ipalloc.CustomPodInterface{
			{
				Name:      ifName,
				IpAddress: ip,
			},
		},
	}
	ev := &controller.KubeStateChange{
		Key:      ipalloc.Key(podID.Name, podID.Namespace),
		Resource: ipalloc.Keyword,
		NewValue: newIf,
	}

	linuxIf := &linux_interfaces.Interface{
		Name:        ifName,
		IpAddresses: []string{ip},
		PhysAddress: mac,
	}

	fixture.ConfigRetriever.AddConfig(linux_interfaces.InterfaceKey(ifName), linuxIf)

	_, err := fixture.IPAM.Update(ev, nil)

	Expect(err).To(BeNil())
	Expect(fixture.Txn.Commit()).To(BeNil())

	err = fixture.SFCProcessor.Update(ev)
	Expect(err).To(BeNil())
	Expect(fixture.Txn.Commit()).To(BeNil())
}

func addPod(podID podmodel.ID, local bool, chainIndex int, fixture *Fixture) net.IP {
	podIP, err := fixture.IPAM.AllocatePodIP(podID, "", "")
	fixture.PodManager.AddRemotePod(&podmanager.Pod{
		ID:        podID,
		IPAddress: podIP.String(),
		Labels:    map[string]string{podSelectorKey: podSelectorValPrefix + strconv.Itoa(chainIndex)},
	})
	if local {
		fixture.PodManager.AddPod(&podmanager.LocalPod{
			ID: podID,
		})
	}
	Expect(err).To(BeNil())
	pod := &podmodel.Pod{
		Name:      podID.Name,
		Namespace: podID.Namespace,
		IpAddress: podIP.String(),
		Labels:    map[string]string{podSelectorKey: podSelectorValPrefix + strconv.Itoa(chainIndex)},
	}
	ev := &controller.KubeStateChange{
		Key:      podmodel.Key(pod.Name, pod.Namespace),
		Resource: podmodel.PodKeyword,
		NewValue: pod,
	}

	Expect(fixture.SFCProcessor.Update(ev)).To(BeNil())
	Expect(fixture.Txn.Commit()).To(BeNil())

	return podIP
}

func hasPolicy(policy *vpp_srv6.Policy, policies map[string]*vpp_srv6.Policy) bool {

	for _, curPolicy := range policies {
		match := true
		match = match && curPolicy.Bsid == policy.Bsid
		match = match && curPolicy.SprayBehaviour == policy.SprayBehaviour
		match = match && curPolicy.SrhEncapsulation == policy.SrhEncapsulation
		match = match && curPolicy.InstallationVrfId == policy.InstallationVrfId

		match = match && len(curPolicy.SegmentLists) == len(policy.SegmentLists)
		for _, sl := range policy.SegmentLists {
			hasSl := false
			for _, currentSl := range curPolicy.SegmentLists {
				weightEqual := sl.Weight == currentSl.Weight
				segmentsEqual := reflect.DeepEqual(sl.Segments, currentSl.Segments)
				hasSl = hasSl || (weightEqual && segmentsEqual)
			}
			match = match && hasSl
		}

		if match {
			return true
		}
	}
	return false
}

func interfaceNames(logicalName, crdName string) *renderer.InterfaceNames {
	return &renderer.InterfaceNames{
		LogicalName: logicalName,
		CRDName:     crdName,
	}
}
