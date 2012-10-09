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

from quantum.openstack.common import cfg

plugin_opts = [
    cfg.StrOpt('ucs_plugin'),
    cfg.StrOpt('nexus_plugin'),
    cfg.StrOpt('vswitch_plugin', default='quantum.plugins.openvswitch.'
               'ovs_quantum_plugin.OVSQuantumPluginV2'),
]

inventory_opts = [
    cfg.StrOpt('ucs_plugin'),
    cfg.StrOpt('nexus_plugin'),
]

vlan_opts = [
    cfg.IntOpt('vlan_start', default=100),
    cfg.IntOpt('vlan_end', default=3000),
    cfg.StrOpt('vlan_name_prefix', default='q-'),
]

port_opts = [
    cfg.IntOpt('max_ports', default=100),
]

portprofile_opts = [
    cfg.IntOpt('max_port_profiles', default=65568),
]

network_opts = [
    cfg.IntOpt('max_networks', default=65568),
]

model_opts = [
    cfg.StrOpt('model_class', default='quantum.plugins.cisco.models.'
               'virt_phy_sw_v2.VirtualPhysicalSwitchModelV2'),
]

segmentation_opts = [
    cfg.StrOpt('manager_class', default='quantum.plugins.cisco.segmentation.'
               'l2network_vlan_mgr_v2.L2NetworkVLANMgr'),
]

database_opts = [
    cfg.StrOpt('sql_connection', default='sqlite://'),
]

credentials_opts = [
    cfg.ListOpt('credentials'),
]

switch_opts = [
    cfg.StrOpt('nexus_ip_address'),
    cfg.StrOpt('ports'),
    cfg.IntOpt('nexus_ssh_port'),
]

nexus_driver_opts = [
    cfg.StrOpt('name', default='quantum.plugins.cisco.nexus.'
               'cisco_nexus_network_driver_v2.CiscoNEXUSDriver'),
]

ucsm_opts = [
    cfg.StrOpt('ip_address'),
    cfg.StrOpt('default_vlan_name', default='default'),
    cfg.IntOpt('default_vlan_id', default=1),
    cfg.IntOpt('max_ucsm_port_profiles', default=1024),
    cfg.StrOpt('profile_name_prefix', default='q-'),
]

ucsm_driver_opts = [
    cfg.StrOpt('name', default='quantum.plugins.cisco.tests.unit.v2.'
               'fake_ucs_driver.CiscoUCSMFakeDriver'),
]

ucsm_inventory_opts = [
    cfg.ListOpt('inventory', default='quantum.plugins.cisco.ucs.'
                'cisco_ucs_inventory_v2')
]

ucsm_fake_inventory_opts = [
    cfg.ListOpt('inventory', default='quantum.plugins.cisco.tests.unit.'
                'v2.ucs.cisco_ucs_inventory_fake')
]

cfg.CONF.register_opts(plugin_opts, "PLUGINS")
cfg.CONF.register_opts(inventory_opts, "INVENTORY")
cfg.CONF.register_opts(vlan_opts, "VLANS")
cfg.CONF.register_opts(port_opts, "PORTS")
cfg.CONF.register_opts(portprofile_opts, "PORTPROFILES")
cfg.CONF.register_opts(network_opts, "NETWORKS")
cfg.CONF.register_opts(model_opts, "MODEL")
cfg.CONF.register_opts(segmentation_opts, "SEGMENTATION")
cfg.CONF.register_opts(database_opts, "DATABASE")
cfg.CONF.register_opts(credentials_opts, "CREDENTIALS")
cfg.CONF.register_opts(switch_opts, "SWITCH")
cfg.CONF.register_opts(nexus_driver_opts, "NEXUS_DRIVER")
cfg.CONF.register_opts(ucsm_opts, "UCSM")
cfg.CONF.register_opts(ucsm_driver_opts, "UCSM_DRIVER")
cfg.CONF.register_opts(ucsm_inventory_opts, "UCSM_INVENTORY")
cfg.CONF.register_opts(ucsm_fake_inventory_opts, "UCSM_FAKE_INVENTORY")
