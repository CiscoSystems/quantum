# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack Foundation.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import contextlib
import os

import mock
from oslo.config import cfg
import testtools

from quantum.agent.linux import ip_lib
from quantum.agent.linux import utils
from quantum.openstack.common.rpc import common as rpc_common
from quantum.plugins.linuxbridge.agent import linuxbridge_quantum_agent
from quantum.plugins.linuxbridge.common import constants as lconst
from quantum.tests import base


class TestLinuxBridge(base.BaseTestCase):

    def setUp(self):
        super(TestLinuxBridge, self).setUp()
        self.addCleanup(cfg.CONF.reset)
        interface_mappings = {'physnet1': 'eth1'}
        root_helper = cfg.CONF.AGENT.root_helper

        self.linux_bridge = linuxbridge_quantum_agent.LinuxBridgeManager(
            interface_mappings, root_helper)

    def test_ensure_physical_in_bridge_invalid(self):
        result = self.linux_bridge.ensure_physical_in_bridge('network_id',
                                                             lconst.TYPE_VLAN,
                                                             'physnetx',
                                                             7)
        self.assertFalse(result)

    def test_ensure_physical_in_bridge_flat(self):
        with mock.patch.object(self.linux_bridge,
                               'ensure_flat_bridge') as flat_bridge_func:
            self.linux_bridge.ensure_physical_in_bridge(
                'network_id', lconst.TYPE_FLAT, 'physnet1', None)
        self.assertTrue(flat_bridge_func.called)

    def test_ensure_physical_in_bridge_vlan(self):
        with mock.patch.object(self.linux_bridge,
                               'ensure_vlan_bridge') as vlan_bridge_func:
            self.linux_bridge.ensure_physical_in_bridge(
                'network_id', lconst.TYPE_VLAN, 'physnet1', 7)
        self.assertTrue(vlan_bridge_func.called)


class TestLinuxBridgeAgent(base.BaseTestCase):

    LINK_SAMPLE = [
        '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue \\'
        'state UNKNOWN \\'
        'link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00',
        '2: eth77: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 \\'
        'qdisc mq state UP qlen 1000\    link/ether \\'
        'cc:dd:ee:ff:ab:cd brd ff:ff:ff:ff:ff:ff']

    def setUp(self):
        super(TestLinuxBridgeAgent, self).setUp()
        cfg.CONF.set_override('rpc_backend',
                              'quantum.openstack.common.rpc.impl_fake')
        self.lbmgr_patcher = mock.patch('quantum.plugins.linuxbridge.agent.'
                                        'linuxbridge_quantum_agent.'
                                        'LinuxBridgeManager')
        self.lbmgr_mock = self.lbmgr_patcher.start()
        self.addCleanup(self.lbmgr_patcher.stop)
        self.execute_p = mock.patch.object(ip_lib.IPWrapper, '_execute')
        self.execute = self.execute_p.start()
        self.addCleanup(self.execute_p.stop)
        self.execute.return_value = '\n'.join(self.LINK_SAMPLE)
        self.get_mac_p = mock.patch('quantum.agent.linux.utils.'
                                    'get_interface_mac')
        self.get_mac = self.get_mac_p.start()
        self.addCleanup(self.get_mac_p.stop)
        self.get_mac.return_value = '00:00:00:00:00:01'

    def test_update_devices_failed(self):
        lbmgr_instance = self.lbmgr_mock.return_value
        lbmgr_instance.update_devices.side_effect = RuntimeError
        agent = linuxbridge_quantum_agent.LinuxBridgeQuantumAgentRPC({},
                                                                     0,
                                                                     None)
        raise_exception = [0]

        def info_mock(msg):
            if raise_exception[0] < 2:
                raise_exception[0] += 1
            else:
                raise RuntimeError()

        with mock.patch.object(linuxbridge_quantum_agent.LOG, 'info') as log:
            log.side_effect = info_mock
            with testtools.ExpectedException(RuntimeError):
                agent.daemon_loop()
            self.assertEqual(3, log.call_count)

    def test_process_network_devices_failed(self):
        device_info = {'current': [1, 2, 3]}
        lbmgr_instance = self.lbmgr_mock.return_value
        lbmgr_instance.update_devices.return_value = device_info
        agent = linuxbridge_quantum_agent.LinuxBridgeQuantumAgentRPC({},
                                                                     0,
                                                                     None)
        raise_exception = [0]

        def info_mock(msg):
            if raise_exception[0] < 2:
                raise_exception[0] += 1
            else:
                raise RuntimeError()

        with contextlib.nested(
            mock.patch.object(linuxbridge_quantum_agent.LOG, 'info'),
            mock.patch.object(agent, 'process_network_devices')
        ) as (log, process_network_devices):
            log.side_effect = info_mock
            process_network_devices.side_effect = RuntimeError
            with testtools.ExpectedException(RuntimeError):
                agent.daemon_loop()
            self.assertEqual(3, log.call_count)


class TestLinuxBridgeManager(base.BaseTestCase):
    def setUp(self):
        super(TestLinuxBridgeManager, self).setUp()
        self.interface_mappings = {'physnet1': 'eth1'}
        self.root_helper = cfg.CONF.AGENT.root_helper

        self.lbm = linuxbridge_quantum_agent.LinuxBridgeManager(
            self.interface_mappings, self.root_helper)

    def test_device_exists(self):
        with mock.patch.object(utils, 'execute') as execute_fn:
            self.assertTrue(self.lbm.device_exists("eth0"))
            execute_fn.side_effect = RuntimeError()
            self.assertFalse(self.lbm.device_exists("eth0"))

    def test_interface_exists_on_bridge(self):
        with mock.patch.object(os, 'listdir') as listdir_fn:
            listdir_fn.return_value = ["abc"]
            self.assertTrue(
                self.lbm.interface_exists_on_bridge("br-int", "abc")
            )
            self.assertFalse(
                self.lbm.interface_exists_on_bridge("br-int", "abd")
            )

    def test_get_bridge_name(self):
        nw_id = "123456789101112"
        self.assertEqual(self.lbm.get_bridge_name(nw_id),
                         "brq" + nw_id[0:11])
        nw_id = ""
        self.assertEqual(self.lbm.get_bridge_name(nw_id),
                         "brq")

    def test_get_subinterface_name(self):
        self.assertEqual(self.lbm.get_subinterface_name("eth0", "0"),
                         "eth0.0")
        self.assertEqual(self.lbm.get_subinterface_name("eth0", ""),
                         "eth0.")

    def test_get_tap_device_name(self):
        if_id = "123456789101112"
        self.assertEqual(self.lbm.get_tap_device_name(if_id),
                         "tap" + if_id[0:11])
        if_id = ""
        self.assertEqual(self.lbm.get_tap_device_name(if_id),
                         "tap")

    def test_get_all_quantum_bridges(self):
        br_list = ["br-int", "brq1", "brq2", "br-ex"]
        with mock.patch.object(os, 'listdir') as listdir_fn:
            listdir_fn.return_value = br_list
            self.assertEqual(self.lbm.get_all_quantum_bridges(),
                             br_list[1:3])
            self.assertTrue(listdir_fn.called)

    def test_get_interfaces_on_bridge(self):
        with contextlib.nested(
            mock.patch.object(utils, 'execute'),
            mock.patch.object(os, 'listdir')
        ) as (exec_fn, listdir_fn):
            listdir_fn.return_value = ["qbr1"]
            self.assertEqual(self.lbm.get_interfaces_on_bridge("br0"),
                             ["qbr1"])

    def test_get_bridge_for_tap_device(self):
        with contextlib.nested(
            mock.patch.object(self.lbm, "get_all_quantum_bridges"),
            mock.patch.object(self.lbm, "get_interfaces_on_bridge")
        ) as (get_all_qbr_fn, get_if_fn):
            get_all_qbr_fn.return_value = ["br-int", "br-ex"]
            get_if_fn.return_value = ["tap1", "tap2", "tap3"]
            self.assertEqual(self.lbm.get_bridge_for_tap_device("tap1"),
                             "br-int")
            self.assertEqual(self.lbm.get_bridge_for_tap_device("tap4"),
                             None)

    def test_is_device_on_bridge(self):
        self.assertTrue(not self.lbm.is_device_on_bridge(""))
        with mock.patch.object(os.path, 'exists') as exists_fn:
            exists_fn.return_value = True
            self.assertTrue(self.lbm.is_device_on_bridge("tap1"))
            exists_fn.assert_called_with(
                "/sys/devices/virtual/net/tap1/brport"
            )

    def test_get_interface_details(self):
        with contextlib.nested(
            mock.patch.object(ip_lib.IpAddrCommand, 'list'),
            mock.patch.object(ip_lib.IpRouteCommand, 'get_gateway')
        ) as (list_fn, getgw_fn):
            gwdict = dict(gateway='1.1.1.1')
            getgw_fn.return_value = gwdict
            ipdict = dict(cidr='1.1.1.1/24',
                          broadcast='1.1.1.255',
                          scope='global',
                          ip_version=4,
                          dynamic=False)
            list_fn.return_value = ipdict
            ret = self.lbm.get_interface_details("eth0")

            self.assertTrue(list_fn.called)
            self.assertTrue(getgw_fn.called)
            self.assertEqual(ret, (ipdict, gwdict))

    def test_ensure_flat_bridge(self):
        with contextlib.nested(
            mock.patch.object(ip_lib.IpAddrCommand, 'list'),
            mock.patch.object(ip_lib.IpRouteCommand, 'get_gateway')
        ) as (list_fn, getgw_fn):
            gwdict = dict(gateway='1.1.1.1')
            getgw_fn.return_value = gwdict
            ipdict = dict(cidr='1.1.1.1/24',
                          broadcast='1.1.1.255',
                          scope='global',
                          ip_version=4,
                          dynamic=False)
            list_fn.return_value = ipdict
            with mock.patch.object(self.lbm, 'ensure_bridge') as ens:
                self.assertEqual(
                    self.lbm.ensure_flat_bridge("123", "eth0"),
                    "eth0"
                )
                self.assertTrue(list_fn.called)
                self.assertTrue(getgw_fn.called)
                ens.assert_called_once_with("brq123", "eth0",
                                            ipdict, gwdict)

    def test_ensure_vlan_bridge(self):
        with contextlib.nested(
            mock.patch.object(self.lbm, 'ensure_vlan'),
            mock.patch.object(self.lbm, 'ensure_bridge'),
            mock.patch.object(self.lbm, 'get_interface_details'),
        ) as (ens_vl_fn, ens, get_int_det_fn):
            ens_vl_fn.return_value = "eth0.1"
            get_int_det_fn.return_value = (None, None)
            self.assertEqual(self.lbm.ensure_vlan_bridge("123", "eth0", "1"),
                             "eth0.1")
            ens.assert_called_with("brq123", "eth0.1", None, None)

            get_int_det_fn.return_value = ("ips", "gateway")
            self.assertEqual(self.lbm.ensure_vlan_bridge("123", "eth0", "1"),
                             "eth0.1")
            ens.assert_called_with("brq123", "eth0.1", "ips", "gateway")

    def test_ensure_local_bridge(self):
        with mock.patch.object(self.lbm, 'ensure_bridge') as ens_fn:
            self.lbm.ensure_local_bridge("54321")
            ens_fn.assert_called_once_with("brq54321")

    def test_ensure_vlan(self):
        with mock.patch.object(self.lbm, 'device_exists') as de_fn:
            de_fn.return_value = True
            self.assertEqual(self.lbm.ensure_vlan("eth0", "1"), "eth0.1")
            de_fn.return_value = False
            with mock.patch.object(utils, 'execute') as exec_fn:
                exec_fn.return_value = False
                self.assertEqual(self.lbm.ensure_vlan("eth0", "1"), "eth0.1")
                exec_fn.assert_called_twice()
                exec_fn.return_value = True
                self.assertIsNone(self.lbm.ensure_vlan("eth0", "1"))
                exec_fn.assert_called_once()

    def test_update_interface_ip_details(self):
        gwdict = dict(gateway='1.1.1.1',
                      metric=50)
        ipdict = dict(cidr='1.1.1.1/24',
                      broadcast='1.1.1.255',
                      scope='global',
                      ip_version=4,
                      dynamic=False)
        with contextlib.nested(
            mock.patch.object(ip_lib.IpAddrCommand, 'add'),
            mock.patch.object(ip_lib.IpAddrCommand, 'delete')
        ) as (add_fn, del_fn):
            self.lbm.update_interface_ip_details("br0", "eth0",
                                                 [ipdict], None)
            self.assertTrue(add_fn.called)
            self.assertTrue(del_fn.called)

        with contextlib.nested(
            mock.patch.object(ip_lib.IpRouteCommand, 'add_gateway'),
            mock.patch.object(ip_lib.IpRouteCommand, 'delete_gateway')
        ) as (addgw_fn, delgw_fn):
            self.lbm.update_interface_ip_details("br0", "eth0",
                                                 None, gwdict)
            self.assertTrue(addgw_fn.called)
            self.assertTrue(delgw_fn.called)

    def test_ensure_bridge(self):
        with contextlib.nested(
            mock.patch.object(self.lbm, 'device_exists'),
            mock.patch.object(utils, 'execute'),
            mock.patch.object(self.lbm, 'update_interface_ip_details'),
            mock.patch.object(self.lbm, 'interface_exists_on_bridge')
        ) as (de_fn, exec_fn, upd_fn, ie_fn):
            de_fn.return_value = False
            exec_fn.return_value = False
            self.assertEqual(self.lbm.ensure_bridge("br0", None), "br0")
            ie_fn.return_Value = False
            self.lbm.ensure_bridge("br0", "eth0")
            upd_fn.assert_called_with("br0", "eth0", None, None)
            ie_fn.assert_called_with("br0", "eth0")

            self.lbm.ensure_bridge("br0", "eth0", "ips", "gateway")
            upd_fn.assert_called_with("br0", "eth0", "ips", "gateway")
            ie_fn.assert_called_with("br0", "eth0")

            exec_fn.side_effect = Exception()
            de_fn.return_value = True
            self.lbm.ensure_bridge("br0", "eth0")
            ie_fn.assert_called_with("br0", "eth0")

    def test_ensure_physical_in_bridge(self):
        self.assertFalse(
            self.lbm.ensure_physical_in_bridge("123", lconst.TYPE_VLAN,
                                               "phys", "1")
        )
        with mock.patch.object(self.lbm, "ensure_flat_bridge") as flbr_fn:
            self.assertTrue(
                self.lbm.ensure_physical_in_bridge("123", lconst.TYPE_FLAT,
                                                   "physnet1", None)
            )
            self.assertTrue(flbr_fn.called)
        with mock.patch.object(self.lbm, "ensure_vlan_bridge") as vlbr_fn:
            self.assertTrue(
                self.lbm.ensure_physical_in_bridge("123", lconst.TYPE_VLAN,
                                                   "physnet1", "1")
            )
            self.assertTrue(vlbr_fn.called)

    def test_add_tap_interface(self):
        with mock.patch.object(self.lbm, "device_exists") as de_fn:
            de_fn.return_value = False
            self.assertFalse(
                self.lbm.add_tap_interface("123", lconst.TYPE_VLAN,
                                           "physnet1", "1", "tap1")
            )

            de_fn.return_value = True
            with contextlib.nested(
                mock.patch.object(self.lbm, "ensure_local_bridge"),
                mock.patch.object(utils, "execute"),
                mock.patch.object(self.lbm, "get_bridge_for_tap_device")
            ) as (en_fn, exec_fn, get_br):
                exec_fn.return_value = False
                get_br.return_value = True
                self.assertTrue(self.lbm.add_tap_interface("123",
                                                           lconst.TYPE_LOCAL,
                                                           "physnet1", None,
                                                           "tap1"))
                en_fn.assert_called_with("123")

                get_br.return_value = False
                exec_fn.return_value = True
                self.assertFalse(self.lbm.add_tap_interface("123",
                                                            lconst.TYPE_LOCAL,
                                                            "physnet1", None,
                                                            "tap1"))

            with mock.patch.object(self.lbm,
                                   "ensure_physical_in_bridge") as ens_fn:
                ens_fn.return_value = False
                self.assertFalse(self.lbm.add_tap_interface("123",
                                                            lconst.TYPE_VLAN,
                                                            "physnet1", "1",
                                                            "tap1"))

    def test_add_interface(self):
        with mock.patch.object(self.lbm, "add_tap_interface") as add_tap:
            self.lbm.add_interface("123", lconst.TYPE_VLAN, "physnet-1",
                                   "1", "234")
            add_tap.assert_called_with("123", lconst.TYPE_VLAN, "physnet-1",
                                       "1", "tap234")

    def test_delete_vlan_bridge(self):
        with contextlib.nested(
            mock.patch.object(self.lbm, "device_exists"),
            mock.patch.object(self.lbm, "get_interfaces_on_bridge"),
            mock.patch.object(self.lbm, "remove_interface"),
            mock.patch.object(self.lbm, "get_interface_details"),
            mock.patch.object(self.lbm, "update_interface_ip_details"),
            mock.patch.object(self.lbm, "delete_vlan"),
            mock.patch.object(utils, "execute")
        ) as (de_fn, getif_fn, remif_fn, if_det_fn,
              updif_fn, del_vlan, exec_fn):
            de_fn.return_value = False
            self.lbm.delete_vlan_bridge("br0")
            self.assertFalse(getif_fn.called)

            de_fn.return_value = True
            getif_fn.return_value = ["eth0", "eth1.1", "eth1"]
            if_det_fn.return_value = ("ips", "gateway")
            exec_fn.return_value = False
            self.lbm.delete_vlan_bridge("br0")
            updif_fn.assert_called_with("eth1", "br0", "ips", "gateway")
            del_vlan.assert_called_with("eth1.1")

    def test_remove_interface(self):
        with contextlib.nested(
            mock.patch.object(self.lbm, "device_exists"),
            mock.patch.object(self.lbm, "is_device_on_bridge"),
            mock.patch.object(utils, "execute")
        ) as (de_fn, isdev_fn, exec_fn):
            de_fn.return_value = False
            self.assertFalse(self.lbm.remove_interface("br0", "eth0"))
            self.assertFalse(isdev_fn.called)

            de_fn.return_value = True
            isdev_fn.return_value = False
            self.assertTrue(self.lbm.remove_interface("br0", "eth0"))

            isdev_fn.return_value = True
            exec_fn.return_value = True
            self.assertFalse(self.lbm.remove_interface("br0", "eth0"))

            exec_fn.return_value = False
            self.assertTrue(self.lbm.remove_interface("br0", "eth0"))

    def test_delete_vlan(self):
        with contextlib.nested(
            mock.patch.object(self.lbm, "device_exists"),
            mock.patch.object(utils, "execute")
        ) as (de_fn, exec_fn):
            de_fn.return_value = False
            self.lbm.delete_vlan("eth1.1")
            self.assertFalse(exec_fn.called)

            de_fn.return_value = True
            exec_fn.return_value = False
            self.lbm.delete_vlan("eth1.1")
            self.assertTrue(exec_fn.called)

    def test_update_devices(self):
        with mock.patch.object(self.lbm, "udev_get_tap_devices") as gt_fn:
            gt_fn.return_value = set(["dev1"])
            self.assertIsNone(self.lbm.update_devices(set(["dev1"])))

            gt_fn.return_value = set(["dev1", "dev2"])
            self.assertEqual(self.lbm.update_devices(set(["dev2", "dev3"])),
                             {"current": set(["dev1", "dev2"]),
                              "added": set(["dev1"]),
                              "removed": set(["dev3"])
                              })


class TestLinuxBridgeRpcCallbacks(base.BaseTestCase):
    def setUp(self):
        super(TestLinuxBridgeRpcCallbacks, self).setUp()

        class FakeLBAgent(object):
            def __init__(self):
                self.agent_id = 1
                self.br_mgr = (linuxbridge_quantum_agent.
                               LinuxBridgeManager({'physnet1': 'eth1'},
                                                  cfg.CONF.AGENT.root_helper))

        self.lb_rpc = linuxbridge_quantum_agent.LinuxBridgeRpcCallbacks(
            object(),
            FakeLBAgent()
        )

    def test_network_delete(self):
        with contextlib.nested(
            mock.patch.object(self.lb_rpc.agent.br_mgr, "get_bridge_name"),
            mock.patch.object(self.lb_rpc.agent.br_mgr, "delete_vlan_bridge")
        ) as (get_br_fn, del_fn):
            get_br_fn.return_value = "br0"
            self.lb_rpc.network_delete("anycontext", network_id="123")
            get_br_fn.assert_called_with("123")
            del_fn.assert_called_with("br0")

    def test_port_update(self):
        with contextlib.nested(
            mock.patch.object(self.lb_rpc.agent.br_mgr,
                              "get_tap_device_name"),
            mock.patch.object(self.lb_rpc.agent.br_mgr,
                              "udev_get_tap_devices"),
            mock.patch.object(self.lb_rpc.agent.br_mgr,
                              "get_bridge_name"),
            mock.patch.object(self.lb_rpc.agent.br_mgr,
                              "remove_interface"),
            mock.patch.object(self.lb_rpc.agent.br_mgr, "add_interface"),
            mock.patch.object(self.lb_rpc.agent,
                              "plugin_rpc", create=True),
            mock.patch.object(self.lb_rpc.sg_agent,
                              "refresh_firewall", create=True)
        ) as (get_tap_fn, udev_fn, getbr_fn, remif_fn,
              addif_fn, rpc_obj, reffw_fn):
            get_tap_fn.return_value = "tap123"
            udev_fn.return_value = ["tap123", "tap124"]
            port = {"admin_state_up": True,
                    "id": "1234-5678",
                    "network_id": "123-123"}
            self.lb_rpc.port_update("unused_context", port=port,
                                    vlan_id="1", physical_network="physnet1")
            self.assertFalse(reffw_fn.called)
            addif_fn.assert_called_with(port["network_id"], lconst.TYPE_VLAN,
                                        "physnet1", "1", port["id"])

            self.lb_rpc.port_update("unused_context", port=port,
                                    network_type=lconst.TYPE_VLAN,
                                    segmentation_id="2",
                                    physical_network="physnet1")
            self.assertFalse(reffw_fn.called)
            addif_fn.assert_called_with(port["network_id"], lconst.TYPE_VLAN,
                                        "physnet1", "2", port["id"])

            self.lb_rpc.port_update("unused_context", port=port,
                                    vlan_id=lconst.FLAT_VLAN_ID,
                                    physical_network="physnet1")
            self.assertFalse(reffw_fn.called)
            addif_fn.assert_called_with(port["network_id"], lconst.TYPE_FLAT,
                                        "physnet1", None, port["id"])

            self.lb_rpc.port_update("unused_context", port=port,
                                    network_type=lconst.TYPE_FLAT,
                                    segmentation_id=None,
                                    physical_network="physnet1")
            self.assertFalse(reffw_fn.called)
            addif_fn.assert_called_with(port["network_id"], lconst.TYPE_FLAT,
                                        "physnet1", None, port["id"])

            self.lb_rpc.port_update("unused_context", port=port,
                                    vlan_id=lconst.LOCAL_VLAN_ID,
                                    physical_network=None)
            self.assertFalse(reffw_fn.called)
            addif_fn.assert_called_with(port["network_id"], lconst.TYPE_LOCAL,
                                        None, None, port["id"])

            self.lb_rpc.port_update("unused_context", port=port,
                                    network_type=lconst.TYPE_LOCAL,
                                    segmentation_id=None,
                                    physical_network=None)
            self.assertFalse(reffw_fn.called)
            addif_fn.assert_called_with(port["network_id"], lconst.TYPE_LOCAL,
                                        None, None, port["id"])

            port["admin_state_up"] = False
            port["security_groups"] = True
            getbr_fn.return_value = "br0"
            self.lb_rpc.port_update("unused_context", port=port,
                                    vlan_id="1", physical_network="physnet1")
            self.assertTrue(reffw_fn.called)
            remif_fn.assert_called_with("br0", "tap123")
            rpc_obj.update_device_down.assert_called_with(
                self.lb_rpc.context,
                "tap123",
                self.lb_rpc.agent.agent_id
            )

    def test_port_update_plugin_rpc_failed(self):
        with contextlib.nested(
                mock.patch.object(self.lb_rpc.agent.br_mgr,
                                  "get_tap_device_name"),
                mock.patch.object(self.lb_rpc.agent.br_mgr,
                                  "udev_get_tap_devices"),
                mock.patch.object(self.lb_rpc.agent.br_mgr,
                                  "get_bridge_name"),
                mock.patch.object(self.lb_rpc.agent.br_mgr,
                                  "remove_interface"),
                mock.patch.object(self.lb_rpc.agent.br_mgr, "add_interface"),
                mock.patch.object(self.lb_rpc.sg_agent,
                                  "refresh_firewall", create=True),
                mock.patch.object(self.lb_rpc.agent,
                                  "plugin_rpc", create=True),
                mock.patch.object(linuxbridge_quantum_agent.LOG, 'error'),
        ) as (get_tap_fn, udev_fn, _, _, _, _, plugin_rpc, log):
            get_tap_fn.return_value = "tap123"
            udev_fn.return_value = ["tap123", "tap124"]
            port = {"admin_state_up": True,
                    "id": "1234-5678",
                    "network_id": "123-123"}
            plugin_rpc.update_device_up.side_effect = rpc_common.Timeout
            self.lb_rpc.port_update(mock.Mock(), port=port)
            self.assertTrue(plugin_rpc.update_device_up.called)
            self.assertEqual(log.call_count, 1)

            log.reset_mock()
            port["admin_state_up"] = False
            plugin_rpc.update_device_down.side_effect = rpc_common.Timeout
            self.lb_rpc.port_update(mock.Mock(), port=port)
            self.assertTrue(plugin_rpc.update_device_down.called)
            self.assertEqual(log.call_count, 1)
