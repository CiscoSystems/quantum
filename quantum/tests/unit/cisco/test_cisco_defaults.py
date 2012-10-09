# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.  All rights reserved.
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
#
# @author: Rohit Agarwalla, Cisco Systems, Inc.

import unittest

from quantum.openstack.common import cfg
from quantum.plugins.cisco.common import config


class ConfigurationTest(unittest.TestCase):

    def test_defaults(self):
        self.assertEqual('quantum.plugins.openvswitch.'
                         'ovs_quantum_plugin.OVSQuantumPluginV2',
                         cfg.CONF.PLUGINS.vswitch_plugin)
        self.assertEqual(100, cfg.CONF.VLANS.vlan_start)
        self.assertEqual(3000, cfg.CONF.VLANS.vlan_end)
        self.assertEqual('q-', cfg.CONF.VLANS.vlan_name_prefix)
        self.assertEqual(100, cfg.CONF.PORTS.max_ports)
        self.assertEqual(65568, cfg.CONF.PORTPROFILES.max_port_profiles)
        self.assertEqual(65568, cfg.CONF.NETWORKS.max_networks)
        self.assertEqual('quantum.plugins.cisco.models.'
                         'virt_phy_sw_v2.VirtualPhysicalSwitchModelV2',
                         cfg.CONF.MODEL.model_class)
        self.assertEqual('quantum.plugins.cisco.segmentation.'
                         'l2network_vlan_mgr_v2.L2NetworkVLANMgr',
                         cfg.CONF.SEGMENTATION.manager_class)
        self.assertEqual('sqlite://', cfg.CONF.DATABASE.sql_connection)
        self.assertEqual('quantum.plugins.cisco.nexus.'
                         'cisco_nexus_network_driver_v2.CiscoNEXUSDriver',
                         cfg.CONF.NEXUS_DRIVER.name)
        self.assertEqual('default', cfg.CONF.UCSM.default_vlan_name)
        self.assertEqual(1, cfg.CONF.UCSM.default_vlan_id)
        self.assertEqual(1024, cfg.CONF.UCSM.max_ucsm_port_profiles)
        self.assertEqual('q-', cfg.CONF.UCSM.profile_name_prefix)
        self.assertEqual('quantum.plugins.cisco.tests.unit.v2.'
                         'fake_ucs_driver.CiscoUCSMFakeDriver',
                         cfg.CONF.UCSM_DRIVER.name)
        self.assertEqual('quantum.plugins.cisco.ucs.'
                         'cisco_ucs_inventory_v2',
                         cfg.CONF.UCSM_INVENTORY.inventory)
        self.assertEqual('quantum.plugins.cisco.tests.unit.'
                         'v2.ucs.cisco_ucs_inventory_fake',
                         cfg.CONF.UCSM_FAKE_INVENTORY.inventory)
