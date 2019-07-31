// Copyright (c) 2017 Cisco and/or its affiliates.
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

package ipnet

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/go-errors/errors"
	. "github.com/onsi/gomega"

	idxmap_mem "github.com/ligato/cn-infra/idxmap/mem"
	"github.com/ligato/cn-infra/infra"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"

	vpp_interfaces "github.com/ligato/vpp-agent/api/models/vpp/interfaces"
	vpp_srv6 "github.com/ligato/vpp-agent/api/models/vpp/srv6"
	scheduler "github.com/ligato/vpp-agent/plugins/kvscheduler/api"

	. "github.com/contiv/vpp/mock/datasync"
	. "github.com/contiv/vpp/mock/eventloop"
	"github.com/contiv/vpp/mock/localclient"
	. "github.com/contiv/vpp/mock/nodesync"
	. "github.com/contiv/vpp/mock/podmanager"
	. "github.com/contiv/vpp/mock/servicelabel"
	"github.com/contiv/vpp/mock/vppagent/handler"

	stn_grpc "github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contivconf"
	"github.com/contiv/vpp/plugins/contivconf/config"
	controller "github.com/contiv/vpp/plugins/controller/api"
	nodeconfig "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	"github.com/contiv/vpp/plugins/ipam"
	k8sPod "github.com/contiv/vpp/plugins/ksr/model/pod"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/nodesync"
	"github.com/contiv/vpp/plugins/podmanager"
)

const (
	// node 1
	node1   = "node1"
	node1ID = 1

	Gbe8           = "GigabitEthernet0/8/0"
	Gbe8IP         = "10.10.10.100/24"
	Gbe9           = "GigabitEthernet0/9/0"
	Gbe9IP         = "10.10.20.5/24"
	GwIP           = "10.10.10.1"
	GwIPWithPrefix = "10.10.10.1/24"

	hostIP1 = "10.3.1.10"
	hostIP2 = "10.0.2.15"

	pod1Container = "<pod1-container-ID>"
	pod1PID       = 124
	pod1Ns        = "/proc/124/ns/net"
	pod1Name      = "pod1"
	pod1Namespace = "default"

	// node 2
	node2Name          = "node2"
	node2ID            = 2
	node2IP            = "10.10.10.200/24"
	node2MgmtIP        = "10.50.50.50"
	node2MgmtIPUpdated = "10.70.70.70"
)

var (
	keyPrefixes = []string{k8sPod.KeyPrefix()}

	hostIPs = []net.IP{net.ParseIP(hostIP1), net.ParseIP(hostIP2)}

	nodeDHCPConfig1 = config.NodeConfig{
		NodeName: node1,
		NodeConfigSpec: nodeconfig.NodeConfigSpec{
			StealInterface: "eth0",
			MainVPPInterface: nodeconfig.InterfaceConfig{
				InterfaceName: Gbe8,
				UseDHCP:       true,
			},
			OtherVPPInterfaces: []nodeconfig.InterfaceConfig{
				{
					InterfaceName: Gbe9,
					IP:            Gbe9IP,
				},
			},
		},
	}

	configTapVxlanDHCP = &config.Config{
		InterfaceConfig: config.InterfaceConfig{
			UseTAPInterfaces:    true,
			TAPInterfaceVersion: 2,
		},
		IPAMConfig: config.IPAMConfig{
			PodSubnetCIDR:                 "10.1.0.0/16",
			PodSubnetOneNodePrefixLen:     24,
			VPPHostSubnetCIDR:             "172.30.0.0/16",
			VPPHostSubnetOneNodePrefixLen: 24,
			NodeInterconnectDHCP:          true,
			VxlanCIDR:                     "192.168.30.0/24",
		},
	}

	noDHCPNodeConfig = config.NodeConfig{
		NodeName: node1,
		NodeConfigSpec: nodeconfig.NodeConfigSpec{
			StealInterface: "eth0",
			MainVPPInterface: nodeconfig.InterfaceConfig{
				InterfaceName: Gbe8,
				IP:            Gbe8IP,
				UseDHCP:       false,
			},
			OtherVPPInterfaces: []nodeconfig.InterfaceConfig{
				{
					InterfaceName: Gbe9,
					IP:            Gbe9IP,
					UseDHCP:       false,
				},
			},
		},
	}

	srv6Config = &config.Config{
		InterfaceConfig: config.InterfaceConfig{
			UseTAPInterfaces:    true,
			TAPInterfaceVersion: 2,
		},
		RoutingConfig: config.RoutingConfig{
			NodeToNodeTransport: "srv6",
			UseSRv6ForServices:  true,
		},
		IPAMConfig: config.IPAMConfig{
			NodeInterconnectCIDR:          "192.168.16.0/24",
			PodSubnetCIDR:                 "10.1.0.0/16",
			PodSubnetOneNodePrefixLen:     24,
			VPPHostSubnetCIDR:             "172.30.0.0/16",
			VPPHostSubnetOneNodePrefixLen: 24,
		},
		NodeConfig: []config.NodeConfig{
			noDHCPNodeConfig,
		},
	}

	/*
		configVethL2NoTCP = &contivconf.Config{
			RoutingConfig: contivconf.RoutingConfig{
				NodeToNodeTransport: contivconf.NoOverlayTransport,
			},
			IPAMConfig: contivconf.IPAMConfig{
				PodSubnetCIDR:                 "10.1.0.0/16",
				PodSubnetOneNodePrefixLen:     24,
				VPPHostSubnetCIDR:             "172.30.0.0/16",
				VPPHostSubnetOneNodePrefixLen: 24,
				NodeInterconnectCIDR:          "192.168.16.0/24",
				VxlanCIDR:                     "192.168.30.0/24",
			},
		}
	*/
)

type Fixture struct {
	Logger       logging.Logger
	EventLoop    *MockEventLoop
	Datasync     *MockDataSync
	ServiceLabel *MockServiceLabel
	NodeSync     *MockNodeSync
	PodManager   *MockPodManager
}

func TestBasicStuff(t *testing.T) {
	RegisterTestingT(t)
	var txnCount int

	fixture := NewFixture("TestBasicStuff")

	// DHCP
	dhcpIndexes := idxmap_mem.NewNamedMapping(logrus.DefaultLogger(), "test-dhcp_indexes", nil)

	// transactions
	txnTracker := localclient.NewTxnTracker(nil)

	// DPDK interfaces
	dpdkIfaces := []string{Gbe8, Gbe9}

	// STN
	stnReply := &stn_grpc.STNReply{
		IpAddresses: []string{Gbe8IP},
		Routes: []*stn_grpc.STNReply_Route{
			{
				DestinationSubnet: "20.20.20.0/24",
				NextHopIp:         "10.10.10.1",
			},
		},
	}

	// contivConf plugin
	contivConf := &contivconf.ContivConf{
		Deps: contivconf.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("contivconf"),
			},
			ServiceLabel: fixture.ServiceLabel,
			UnitTestDeps: &contivconf.UnitTestDeps{
				Config: configTapVxlanDHCP,
				DumpDPDKInterfacesClb: func() ([]string, error) {
					return dpdkIfaces, nil
				},
				RequestSTNInfoClb: requestSTNInfo("eth0", stnReply),
			},
		},
	}
	Expect(contivConf.Init()).To(BeNil())
	resyncEv, _ := fixture.Datasync.ResyncEvent()
	Expect(contivConf.Resync(resyncEv, resyncEv.KubeState, 1, nil)).To(BeNil())

	// IPAM real plugin
	ipam := &ipam.IPAM{
		Deps: ipam.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("IPAM"),
			},
			NodeSync:   fixture.NodeSync,
			ContivConf: contivConf,
		},
	}

	// ipNet plugin
	externalState := &externalState{
		test:      true,
		dhcpIndex: dhcpIndexes,
		hostLinkIPsDump: func() ([]net.IP, error) {
			return hostIPs, nil
		},
	}
	deps := Deps{
		PluginDeps: infra.PluginDeps{
			Log: logging.ForPlugin("ipnet"),
		},
		EventLoop:    fixture.EventLoop,
		ServiceLabel: fixture.ServiceLabel,
		ContivConf:   contivConf,
		IPAM:         ipam,
		NodeSync:     fixture.NodeSync,
		PodManager:   fixture.PodManager,
	}
	plugin := IPNet{
		Deps: deps,
		internalState: &internalState{
			pendingAddPodCustomIf: map[podmodel.ID]bool{},
		},
		externalState: externalState,
	}

	fixture.Datasync.RestartResyncCount()

	fmt.Println("Resync against empty K8s state ---------------------------")

	// resync against empty K8s state data
	resyncEv, resyncCount := fixture.Datasync.ResyncEvent(keyPrefixes...)
	Expect(contivConf.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	Expect(ipam.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	txn := txnTracker.NewControllerTxn(true)
	err := plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
	Expect(plugin.nodeIP).To(BeEmpty())
	Expect(plugin.nodeIPNet).To(BeNil())

	fmt.Println("Resync after DHCP event ----------------------------------")

	// simulate DHCP event
	dhcpIndexes.Put(Gbe8, &vpp_interfaces.DHCPLease{InterfaceName: Gbe8, HostIpAddress: Gbe8IP, RouterIpAddress: GwIPWithPrefix})
	Eventually(fixture.EventLoop.EventQueue).Should(HaveLen(1))
	event := fixture.EventLoop.EventQueue[0]
	nodeIPv4Change, isNodeIPv4Change := event.(*NodeIPv4Change)
	Expect(isNodeIPv4Change).To(BeTrue())
	nodeIP := &net.IPNet{IP: nodeIPv4Change.NodeIP, Mask: nodeIPv4Change.NodeIPNet.Mask}
	Expect(nodeIP.String()).To(Equal(Gbe8IP))
	gwIP := strings.Split(GwIPWithPrefix, "/")[0]
	Expect(nodeIPv4Change.DefaultGw.String()).To(Equal(gwIP))

	resyncEv, resyncCount = fixture.Datasync.ResyncEvent(keyPrefixes...)
	txn = txnTracker.NewControllerTxn(true)
	err = plugin.Resync(nodeIPv4Change, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
	nodeIP = &net.IPNet{IP: plugin.nodeIP, Mask: plugin.nodeIPNet.Mask}
	Expect(nodeIP.String()).To(Equal(Gbe8IP))

	fmt.Println("Add another node -----------------------------------------")

	// add another node
	addr, network, _ := net.ParseCIDR(node2IP)
	mgmt := net.ParseIP(node2MgmtIP)
	node2 := &nodesync.Node{
		Name:            node2Name,
		ID:              node2ID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: addr, Network: network}},
		MgmtIPAddresses: []net.IP{mgmt},
	}
	nodeUpdateEvent := fixture.NodeSync.UpdateNode(node2)
	txn = txnTracker.NewControllerTxn(false)
	change, err := plugin.Update(nodeUpdateEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("connect node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Other node Mgmt IP update --------------------------------")

	// update another node
	mgmt = net.ParseIP(node2MgmtIPUpdated)
	node2Update := &nodesync.Node{
		Name:            node2Name,
		ID:              node2ID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: addr, Network: network}},
		MgmtIPAddresses: []net.IP{mgmt},
	}
	nodeUpdateEvent = fixture.NodeSync.UpdateNode(node2Update)
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(nodeUpdateEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("update node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Add pod --------------------------------------------------")

	// add pod
	pod1ID := k8sPod.ID{Name: pod1Name, Namespace: pod1Namespace}
	addPodEvent := fixture.PodManager.AddPod(&podmanager.LocalPod{
		ID:               pod1ID,
		ContainerID:      pod1Container,
		NetworkNamespace: pod1Ns,
	})
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(addPodEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("configure IP connectivity"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Resync with non-empty K8s state --------------------------")

	// resync now with the IP from DHCP, new pod and the other node
	resyncEv, resyncCount = fixture.Datasync.ResyncEvent(keyPrefixes...)
	txn = txnTracker.NewControllerTxn(true)
	err = plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	// add pod entry into the mock DB
	fixture.Datasync.Put(k8sPod.Key(pod1Name, pod1Namespace), &k8sPod.Pod{
		Namespace: pod1Namespace,
		Name:      pod1Name,
		IpAddress: ipam.GetPodIP(pod1ID).IP.String(),
	})

	fmt.Println("Restart (without node IP) --------------------------------")

	// restart
	plugin = IPNet{
		Deps:          deps,
		internalState: &internalState{},
		externalState: externalState,
	}
	fixture.Datasync.RestartResyncCount()
	// resync
	resyncEv, resyncCount = fixture.Datasync.ResyncEvent(keyPrefixes...)
	txn = txnTracker.NewControllerTxn(true)
	err = plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
	Expect(plugin.nodeIP).To(BeEmpty())
	Expect(plugin.nodeIPNet).To(BeNil())

	fmt.Println("Delete pod -----------------------------------------------")

	// delete pod
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(&podmanager.DeletePod{Pod: pod1ID}, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("un-configure IP connectivity"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	// remove the pod entry from mock podmanager and DB
	fixture.PodManager.DeletePod(pod1ID)
	fixture.Datasync.Delete(k8sPod.Key(pod1Name, pod1Namespace))

	fmt.Println("Delete node ----------------------------------------------")

	// delete the other node
	nodeUpdateEvent = fixture.NodeSync.DeleteNode(node2Name)
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(nodeUpdateEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("disconnect node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Resync just before Close ---------------------------------")

	resyncEv, resyncCount = fixture.Datasync.ResyncEvent(keyPrefixes...)
	txn = txnTracker.NewControllerTxn(true)
	err = plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	fmt.Println("Close ----------------------------------------------------")

	shutdownEvent := &controller.Shutdown{}
	txn = txnTracker.NewControllerTxn(false)
	change, err = plugin.Update(shutdownEvent, txn)
	Expect(err).To(BeNil())
	// nothing needs to be cleaned up for TAPs
	Expect(change).To(Equal(""))
	Expect(txn.Values).To(BeEmpty())
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
}

type TunnelTestingData struct {
	*Fixture
	contivConf  *contivconf.ContivConf
	srv6Handler *handler.SRv6MockHandler
	ipam        *ipam.IPAM
	ipNet       *IPNet
}

func TestPodTunnelIPv4(t *testing.T) {
	RegisterTestingT(t)
	var txnCount int

	fixture := NewFixture("TestPodTunnelIPv4")
	data := newTunnelTestingData(fixture, 4)
	srv6Handler := data.srv6Handler
	contivConf := data.contivConf
	plugin := data.ipNet
	ipam := data.ipam

	txnTracker := localclient.NewTxnTracker(srv6Handler.ApplyTxn)

	fmt.Println("Resync against empty K8s state ---------------------------")

	// resync against empty K8s state data
	resyncEv, resyncCount := fixture.Datasync.ResyncEvent(keyPrefixes...)
	Expect(contivConf.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	Expect(ipam.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	txn := txnTracker.NewControllerTxn(true)
	err := plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
	nodeIP := &net.IPNet{IP: plugin.nodeIP, Mask: plugin.nodeIPNet.Mask}
	Expect(nodeIP.String()).To(Equal(Gbe8IP))

	podTunnelEgressLocalSid := &vpp_srv6.LocalSID{
		Sid:               ipam.SidForNodeToNodePodLocalsid(nodeIP.IP).String(),
		InstallationVrfId: contivConf.GetRoutingConfig().MainVRFID,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_DT4{EndFunction_DT4: &vpp_srv6.LocalSID_EndDT4{
			VrfId: contivConf.GetRoutingConfig().PodVRFID,
		}},
	}
	Expect(srv6Handler.LocalSids).To(ContainElement(podTunnelEgressLocalSid))

	fmt.Println("Add another node -----------------------------------------")

	// add another node
	addr, network, _ := data.ipam.NodeIPAddress(node2ID)
	mgmt := net.ParseIP(node2MgmtIP)
	node2 := &nodesync.Node{
		Name:            node2Name,
		ID:              node2ID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: addr, Network: network}},
		MgmtIPAddresses: []net.IP{mgmt},
	}
	nodeUpdateEvent := fixture.NodeSync.UpdateNode(node2)
	txn = txnTracker.NewControllerTxn(false)
	change, err := plugin.Update(nodeUpdateEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("connect node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	assertIngress(ipam, contivConf, plugin, srv6Handler)
}

func TestPodTunnelIPv6(t *testing.T) {
	RegisterTestingT(t)
	var txnCount int

	fixture := NewFixture("TestPodTunnelIPv6")
	data := newTunnelTestingData(fixture, 6)
	srv6Handler := data.srv6Handler
	contivConf := data.contivConf
	plugin := data.ipNet
	ipam := data.ipam

	txnTracker := localclient.NewTxnTracker(srv6Handler.ApplyTxn)

	fmt.Println("Resync against empty K8s state ---------------------------")

	// resync against empty K8s state data
	resyncEv, resyncCount := fixture.Datasync.ResyncEvent(keyPrefixes...)
	Expect(contivConf.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	Expect(ipam.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	txn := txnTracker.NewControllerTxn(true)
	err := plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
	nodeIP := &net.IPNet{IP: plugin.nodeIP, Mask: plugin.nodeIPNet.Mask}
	Expect(nodeIP.String()).To(Equal(Gbe8IP))

	podTunnelEgressLocalSid := &vpp_srv6.LocalSID{
		Sid:               ipam.SidForNodeToNodePodLocalsid(nodeIP.IP).String(),
		InstallationVrfId: contivConf.GetRoutingConfig().MainVRFID,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_DT6{EndFunction_DT6: &vpp_srv6.LocalSID_EndDT6{
			VrfId: contivConf.GetRoutingConfig().PodVRFID,
		}},
	}
	Expect(srv6Handler.LocalSids).To(ContainElement(podTunnelEgressLocalSid))

	fmt.Println("Add another node -----------------------------------------")

	// add another node
	addr, network, _ := data.ipam.NodeIPAddress(node2ID)
	mgmt := net.ParseIP(node2MgmtIP)
	node2 := &nodesync.Node{
		Name:            node2Name,
		ID:              node2ID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: addr, Network: network}},
		MgmtIPAddresses: []net.IP{mgmt},
	}
	nodeUpdateEvent := fixture.NodeSync.UpdateNode(node2)
	txn = txnTracker.NewControllerTxn(false)
	change, err := plugin.Update(nodeUpdateEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("connect node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	assertIngress(ipam, contivConf, plugin, srv6Handler)
}

func TestHostTunnelIPv4(t *testing.T) {
	RegisterTestingT(t)
	var txnCount int

	fixture := NewFixture("TestHostTunnelIPv4")
	data := newTunnelTestingData(fixture, 4)
	srv6Handler := data.srv6Handler
	contivConf := data.contivConf
	plugin := data.ipNet
	ipam := data.ipam

	txnTracker := localclient.NewTxnTracker(srv6Handler.ApplyTxn)

	fmt.Println("Resync against empty K8s state ---------------------------")

	// resync against empty K8s state data
	resyncEv, resyncCount := fixture.Datasync.ResyncEvent(keyPrefixes...)
	Expect(contivConf.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	Expect(ipam.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	txn := txnTracker.NewControllerTxn(true)
	err := plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
	nodeIP := &net.IPNet{IP: plugin.nodeIP, Mask: plugin.nodeIPNet.Mask}
	Expect(nodeIP.String()).To(Equal(Gbe8IP))

	hostTunnelEgressLocalSid := &vpp_srv6.LocalSID{
		Sid:               ipam.SidForNodeToNodeHostLocalsid(nodeIP.IP).String(),
		InstallationVrfId: contivConf.GetRoutingConfig().MainVRFID,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_DT4{EndFunction_DT4: &vpp_srv6.LocalSID_EndDT4{
			VrfId: contivConf.GetRoutingConfig().MainVRFID,
		}},
	}
	Expect(srv6Handler.LocalSids).To(ContainElement(hostTunnelEgressLocalSid))

	fmt.Println("Add another node -----------------------------------------")

	// add another node
	addr, network, _ := data.ipam.NodeIPAddress(node2ID)
	mgmt := net.ParseIP(node2MgmtIP)
	node2 := &nodesync.Node{
		Name:            node2Name,
		ID:              node2ID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: addr, Network: network}},
		MgmtIPAddresses: []net.IP{mgmt},
	}
	nodeUpdateEvent := fixture.NodeSync.UpdateNode(node2)
	txn = txnTracker.NewControllerTxn(false)
	change, err := plugin.Update(nodeUpdateEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("connect node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	assertIngress(ipam, contivConf, plugin, srv6Handler)
}

func TestHostTunnelIPv6(t *testing.T) {
	RegisterTestingT(t)
	var txnCount int

	fixture := NewFixture("TestHostTunnelIPv6")
	data := newTunnelTestingData(fixture, 6)
	srv6Handler := data.srv6Handler
	contivConf := data.contivConf
	plugin := data.ipNet
	ipam := data.ipam

	txnTracker := localclient.NewTxnTracker(srv6Handler.ApplyTxn)

	fmt.Println("Resync against empty K8s state ---------------------------")

	// resync against empty K8s state data
	resyncEv, resyncCount := fixture.Datasync.ResyncEvent(keyPrefixes...)
	Expect(contivConf.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	Expect(ipam.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	txn := txnTracker.NewControllerTxn(true)
	err := plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
	nodeIP := &net.IPNet{IP: plugin.nodeIP, Mask: plugin.nodeIPNet.Mask}
	Expect(nodeIP.String()).To(Equal(Gbe8IP))

	hostTunnelEgressLocalSid := &vpp_srv6.LocalSID{
		Sid:               ipam.SidForNodeToNodeHostLocalsid(nodeIP.IP).String(),
		InstallationVrfId: contivConf.GetRoutingConfig().MainVRFID,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_DT6{EndFunction_DT6: &vpp_srv6.LocalSID_EndDT6{
			VrfId: contivConf.GetRoutingConfig().MainVRFID,
		}},
	}
	Expect(srv6Handler.LocalSids).To(ContainElement(hostTunnelEgressLocalSid))

	fmt.Println("Add another node -----------------------------------------")

	// add another node
	addr, network, _ := data.ipam.NodeIPAddress(node2ID)
	mgmt := net.ParseIP(node2MgmtIP)
	node2 := &nodesync.Node{
		Name:            node2Name,
		ID:              node2ID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: addr, Network: network}},
		MgmtIPAddresses: []net.IP{mgmt},
	}
	nodeUpdateEvent := fixture.NodeSync.UpdateNode(node2)
	txn = txnTracker.NewControllerTxn(false)
	change, err := plugin.Update(nodeUpdateEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("connect node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	assertIngress(ipam, contivConf, plugin, srv6Handler)
}

func TestIntermServiceTunnelIPv4(t *testing.T) {
	RegisterTestingT(t)
	var txnCount int

	fixture := NewFixture("TestIntermServiceTunnelIPv4")
	data := newTunnelTestingData(fixture, 4)
	srv6Handler := data.srv6Handler
	contivConf := data.contivConf
	plugin := data.ipNet
	ipam := data.ipam

	txnTracker := localclient.NewTxnTracker(srv6Handler.ApplyTxn)

	fmt.Println("Resync against empty K8s state ---------------------------")

	// resync against empty K8s state data
	resyncEv, resyncCount := fixture.Datasync.ResyncEvent(keyPrefixes...)
	Expect(contivConf.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	Expect(ipam.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	txn := txnTracker.NewControllerTxn(true)
	err := plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
	nodeIP := &net.IPNet{IP: plugin.nodeIP, Mask: plugin.nodeIPNet.Mask}
	Expect(nodeIP.String()).To(Equal(Gbe8IP))

	hostTunnelEgressLocalSid := &vpp_srv6.LocalSID{
		Sid:               ipam.SidForNodeToNodeHostLocalsid(nodeIP.IP).String(),
		InstallationVrfId: contivConf.GetRoutingConfig().MainVRFID,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_DT4{EndFunction_DT4: &vpp_srv6.LocalSID_EndDT4{
			VrfId: contivConf.GetRoutingConfig().MainVRFID,
		}},
	}
	Expect(srv6Handler.LocalSids).To(ContainElement(hostTunnelEgressLocalSid))

	fmt.Println("Add another node -----------------------------------------")

	// add another node
	addr, network, _ := data.ipam.NodeIPAddress(node2ID)
	mgmt := net.ParseIP(node2MgmtIP)
	node2 := &nodesync.Node{
		Name:            node2Name,
		ID:              node2ID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: addr, Network: network}},
		MgmtIPAddresses: []net.IP{mgmt},
	}
	nodeUpdateEvent := fixture.NodeSync.UpdateNode(node2)
	txn = txnTracker.NewControllerTxn(false)
	change, err := plugin.Update(nodeUpdateEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("connect node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	assertIngress(ipam, contivConf, plugin, srv6Handler)
}

func TestIntermServiceTunnelIPv6(t *testing.T) {
	RegisterTestingT(t)
	var txnCount int

	fixture := NewFixture("TestIntermServiceTunnelIPv6")
	data := newTunnelTestingData(fixture, 6)
	srv6Handler := data.srv6Handler
	contivConf := data.contivConf
	plugin := data.ipNet
	ipam := data.ipam

	txnTracker := localclient.NewTxnTracker(srv6Handler.ApplyTxn)

	fmt.Println("Resync against empty K8s state ---------------------------")

	// resync against empty K8s state data
	resyncEv, resyncCount := fixture.Datasync.ResyncEvent(keyPrefixes...)
	Expect(contivConf.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	Expect(ipam.Resync(resyncEv, resyncEv.KubeState, resyncCount, nil)).To(BeNil())
	txn := txnTracker.NewControllerTxn(true)
	err := plugin.Resync(resyncEv, resyncEv.KubeState, resyncCount, txn)
	Expect(err).To(BeNil())
	err = commitTransaction(txn, true)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))
	nodeIP := &net.IPNet{IP: plugin.nodeIP, Mask: plugin.nodeIPNet.Mask}
	Expect(nodeIP.String()).To(Equal(Gbe8IP))

	hostTunnelEgressLocalSid := &vpp_srv6.LocalSID{
		Sid:               ipam.SidForNodeToNodeHostLocalsid(nodeIP.IP).String(),
		InstallationVrfId: contivConf.GetRoutingConfig().MainVRFID,
		EndFunction: &vpp_srv6.LocalSID_EndFunction_DT6{EndFunction_DT6: &vpp_srv6.LocalSID_EndDT6{
			VrfId: contivConf.GetRoutingConfig().MainVRFID,
		}},
	}
	Expect(srv6Handler.LocalSids).To(ContainElement(hostTunnelEgressLocalSid))

	fmt.Println("Add another node -----------------------------------------")

	// add another node
	addr, network, _ := data.ipam.NodeIPAddress(node2ID)
	mgmt := net.ParseIP(node2MgmtIP)
	node2 := &nodesync.Node{
		Name:            node2Name,
		ID:              node2ID,
		VppIPAddresses:  contivconf.IPsWithNetworks{{Address: addr, Network: network}},
		MgmtIPAddresses: []net.IP{mgmt},
	}
	nodeUpdateEvent := fixture.NodeSync.UpdateNode(node2)
	txn = txnTracker.NewControllerTxn(false)
	change, err := plugin.Update(nodeUpdateEvent, txn)
	Expect(err).To(BeNil())
	Expect(change).To(Equal("connect node ID=2"))
	err = commitTransaction(txn, false)
	Expect(err).To(BeNil())
	txnCount++
	Expect(txnTracker.PendingTxns).To(HaveLen(0))
	Expect(txnTracker.CommittedTxns).To(HaveLen(txnCount))

	assertIngress(ipam, contivConf, plugin, srv6Handler)
}

func assertIngress(ipam *ipam.IPAM, contivConf *contivconf.ContivConf, plugin *IPNet, srv6Handler *handler.SRv6MockHandler) {
	node2IP, _, err := ipam.NodeIPAddress(node2ID)

	nodeToNodePodSl := &vpp_srv6.Policy_SegmentList{
		Weight: 1,
		Segments: []string{
			ipam.SidForNodeToNodePodLocalsid(node2IP).String(),
		},
	}

	Expect(err).To(BeNil())
	nodeToNodePodPolicy := &vpp_srv6.Policy{
		Bsid:              ipam.BsidForNodeToNodePodPolicy(node2IP).String(),
		InstallationVrfId: contivConf.GetRoutingConfig().MainVRFID,
		SrhEncapsulation:  true,
		SprayBehaviour:    false,
		SegmentLists: []*vpp_srv6.Policy_SegmentList{
			nodeToNodePodSl,
		},
	}

	nodeToNodeHostSl := &vpp_srv6.Policy_SegmentList{
		Weight: 1,
		Segments: []string{
			ipam.SidForNodeToNodeHostLocalsid(node2IP).String(),
		},
	}

	Expect(err).To(BeNil())
	nodeToNodeHostPolicy := &vpp_srv6.Policy{
		Bsid:              ipam.BsidForNodeToNodeHostPolicy(node2IP).String(),
		InstallationVrfId: contivConf.GetRoutingConfig().MainVRFID,
		SrhEncapsulation:  true,
		SprayBehaviour:    false,
		SegmentLists: []*vpp_srv6.Policy_SegmentList{
			nodeToNodeHostSl,
		},
	}
	Expect(srv6Handler.Policies).To(HaveLen(2))
	Expect(hasPolicy(nodeToNodePodPolicy, srv6Handler.Policies)).To(Equal(true))
	Expect(hasPolicy(nodeToNodeHostPolicy, srv6Handler.Policies)).To(Equal(true))

	podNetwork, err := ipam.PodSubnetOtherNode(node2ID)
	assertSteering(podNetwork,
		ipam.BsidForNodeToNodePodPolicy(node2IP),
		"lookupInPodVRF",
		contivConf.GetRoutingConfig().MainVRFID,
		srv6Handler.Steerings)

	hostNetwork, err := ipam.HostInterconnectSubnetOtherNode(node2ID)
	assertSteering(hostNetwork,
		ipam.BsidForNodeToNodeHostPolicy(node2IP),
		"lookupInMainVRF",
		contivConf.GetRoutingConfig().MainVRFID,
		srv6Handler.Steerings)

	_, mgmtNetwork, err := net.ParseCIDR(node2MgmtIP + "/32")
	assertSteering(mgmtNetwork,
		ipam.BsidForNodeToNodeHostPolicy(node2IP),
		"managementIP-"+node2MgmtIP,
		contivConf.GetRoutingConfig().MainVRFID,
		srv6Handler.Steerings)
}

func newTunnelTestingData(fixture *Fixture, ipVer uint8) *TunnelTestingData {

	data := TunnelTestingData{
		Fixture:     fixture,
		srv6Handler: handler.NewSRv6Mock(logrus.DefaultLogger()),
	}

	// DPDK interfaces
	dpdkIfaces := []string{Gbe8, Gbe9}

	// STN
	stnReply := &stn_grpc.STNReply{
		IpAddresses: []string{Gbe8IP},
		Routes: []*stn_grpc.STNReply_Route{
			{
				DestinationSubnet: "20.20.20.0/24",
				NextHopIp:         "10.10.10.1",
			},
		},
	}

	// contivConf plugin
	data.contivConf = &contivconf.ContivConf{
		Deps: contivconf.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("contivconf"),
			},
			ServiceLabel: fixture.ServiceLabel,
			UnitTestDeps: &contivconf.UnitTestDeps{
				Config: srv6Config,
				DumpDPDKInterfacesClb: func() ([]string, error) {
					return dpdkIfaces, nil
				},
				RequestSTNInfoClb: requestSTNInfo("eth0", stnReply),
			},
		},
	}
	Expect(data.contivConf.Init()).To(BeNil())
	resyncEv, _ := data.Datasync.ResyncEvent()
	Expect(data.contivConf.Resync(resyncEv, resyncEv.KubeState, 1, nil)).To(BeNil())

	// IPAM real plugin
	data.ipam = &ipam.IPAM{
		Deps: ipam.Deps{
			PluginDeps: infra.PluginDeps{
				Log: logging.ForPlugin("IPAM"),
			},
			NodeSync:   fixture.NodeSync,
			ContivConf: data.contivConf,
		},
	}
	data.ipam.ContivConf.GetIPAMConfig().UseIPv6 = ipVer == 6

	// ipNet plugin
	externalState := &externalState{
		test: true,
		//dhcpIndex: dhcpIndexes,
		hostLinkIPsDump: func() ([]net.IP, error) {
			return hostIPs, nil
		},
	}
	deps := Deps{
		PluginDeps: infra.PluginDeps{
			Log: logging.ForPlugin("ipnet"),
		},
		EventLoop:    fixture.EventLoop,
		ServiceLabel: fixture.ServiceLabel,
		ContivConf:   data.contivConf,
		IPAM:         data.ipam,
		NodeSync:     fixture.NodeSync,
		PodManager:   fixture.PodManager,
	}
	data.ipNet = &IPNet{
		Deps: deps,
		internalState: &internalState{
			pendingAddPodCustomIf: map[podmodel.ID]bool{},
		},
		externalState: externalState,
	}

	data.Datasync.RestartResyncCount()
	return &data
}

// NewFixture inits and composes together plugins needed for proper rendering unit testing
func NewFixture(testName string) *Fixture {
	fixture := &Fixture{}

	// Logger
	fixture.Logger = logrus.DefaultLogger()
	fixture.Logger.SetLevel(logging.DebugLevel)
	fixture.Logger.Debug(testName)

	// event loop
	fixture.EventLoop = &MockEventLoop{}

	// Datasync
	fixture.Datasync = NewMockDataSync()

	// mock service label
	fixture.ServiceLabel = NewMockServiceLabel()
	fixture.ServiceLabel.SetAgentLabel(node1)

	// nodesync
	fixture.NodeSync = NewMockNodeSync(node1)
	fixture.NodeSync.UpdateNode(&nodesync.Node{
		ID:   node1ID,
		Name: node1,
	})
	Expect(fixture.NodeSync.GetNodeID()).To(BeEquivalentTo(1))

	fixture.Datasync.RestartResyncCount()

	// podmanager
	fixture.PodManager = NewMockPodManager()

	return fixture
}

func hasPolicy(policy *vpp_srv6.Policy, policies map[string]*vpp_srv6.Policy) bool {

	for _, curPolicy := range policies {
		match := true
		match = match && curPolicy.Bsid == policy.Bsid // order of segments in SegmentList flip sometimes = unstable test -> compare by attributes
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

func assertSteering(networkToSteer *net.IPNet, bsid net.IP, nameSuffix string, mainVrfId uint32, steerings map[string]*vpp_srv6.Steering) {
	steering := &vpp_srv6.Steering{
		Name: fmt.Sprintf("forNodeToNodeTunneling-usingPolicyWithBSID-%v-and-%v", bsid.String(), nameSuffix),
		Traffic: &vpp_srv6.Steering_L3Traffic_{
			L3Traffic: &vpp_srv6.Steering_L3Traffic{
				PrefixAddress:     networkToSteer.String(),
				InstallationVrfId: mainVrfId,
			},
		},
		PolicyRef: &vpp_srv6.Steering_PolicyBsid{
			PolicyBsid: bsid.String(),
		},
	}
	Expect(steerings).To(ContainElement(steering))
}

func commitTransaction(txn controller.Transaction, isResync bool) error {
	ctx := context.Background()
	if isResync {
		ctx = scheduler.WithResync(ctx, scheduler.FullResync, true)
	}
	_, err := txn.Commit(ctx)
	return err
}

// requestSTNInfo is a factory for contivconf.RequestSTNInfoClb
func requestSTNInfo(expInterface string, reply *stn_grpc.STNReply) contivconf.RequestSTNInfoClb {
	return func(ifName string) (*stn_grpc.STNReply, error) {
		if ifName != expInterface {
			return nil, errors.New("not the expected stolen interface")
		}
		return reply, nil
	}
}
