# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cisco Systems, Inc.
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

from oslo.config import cfg

from quantum.agent.common import config


cisco_test_opts = [
    cfg.StrOpt('host',
               default=None,
               help=_("Cisco test host option.")),
]

cisco_plugins_opts = [
    cfg.StrOpt('vswitch_plugin',
               default='quantum.plugins.openvswitch.ovs_quantum_plugin.'
                       'OVSQuantumPluginV2',
               help=_("Virtual Switch to use")),
    cfg.StrOpt('nexus_plugin',
               default='quantum.plugins.cisco.nexus.cisco_nexus_plugin_v2.'
                       'NexusPlugin',
               help=_("Nexus Switch to use")),
]

cisco_opts = [
    cfg.StrOpt('vlan_start', default='100',
               help=_("VLAN start value")),
    cfg.StrOpt('vlan_end', default='3000',
               help=_("VLAN end value")),
    cfg.StrOpt('vlan_name_prefix', default='q-',
               help=_("VLAN Name prefix")),
    cfg.StrOpt('max_ports', default='100',
               help=_("Maximum Port value")),
    cfg.StrOpt('max_port_profiles', default='65568',
               help=_("Maximum Port Profile value")),
    cfg.StrOpt('max_networks', default='65568',
               help=_("Maximum Network value")),
    cfg.BoolOpt('svi_round_robin', default=False,
                help=_("Distribute SVI interfaces over all switches")),
    cfg.StrOpt('model_class',
               default='quantum.plugins.cisco.models.virt_phy_sw_v2.'
                       'VirtualPhysicalSwitchModelV2',
               help=_("Model Class")),
    cfg.StrOpt('manager_class',
               default='quantum.plugins.cisco.segmentation.'
                       'l2network_vlan_mgr_v2.L2NetworkVLANMgr',
               help=_("Manager Class")),
    cfg.StrOpt('nexus_driver',
               default='quantum.plugins.cisco.test.nexus.'
                       'fake_nexus_driver.CiscoNEXUSFakeDriver',
               help=_("Nexus Driver Name")),
]

cisco_n1k_opts = [
    cfg.StrOpt('integration_bridge', default='br-int',
               help=_("N1K Integration Bridge")),
    cfg.BoolOpt('enable_tunneling', default=True,
                help=_("N1K Enable Tunneling")),
    cfg.StrOpt('tunnel_bridge', default='br-tun',
               help=_("N1K Tunnel Bridge")),
    cfg.StrOpt('local_ip', default='10.0.0.3',
               help=_("N1K Local IP")),
    cfg.StrOpt('tenant_network_type', default='local',
               help=_("N1K Tenant Network Type")),
    cfg.StrOpt('bridge_mappings', default='',
               help=_("N1K Bridge Mappings")),
    cfg.StrOpt('vxlan_id_ranges', default='5000:10000',
               help=_("N1K VXLAN ID Ranges")),
    cfg.StrOpt('network_vlan_ranges', default='vlan:1:4095',
               help=_("N1K Network VLAN Ranges")),
    cfg.StrOpt('default_policy_profile', default='service_profile',
               help=_("N1K default policy profile")),
]

cfg.CONF.register_opts(cisco_opts, "CISCO")
cfg.CONF.register_opts(cisco_n1k_opts, "CISCO_N1K")
cfg.CONF.register_opts(cisco_plugins_opts, "CISCO_PLUGINS")
cfg.CONF.register_opts(cisco_test_opts, "CISCO_TEST")
config.register_root_helper(cfg.CONF)

# shortcuts
CISCO = cfg.CONF.CISCO
CISCO_N1K = cfg.CONF.CISCO_N1K
CISCO_PLUGINS = cfg.CONF.CISCO_PLUGINS
CISCO_TEST = cfg.CONF.CISCO_TEST

#
# device_dictionary - Contains all external device configuration.
#
# When populated the device dictionary format is:
# {('<device ID>', '<device ipaddr>', '<keyword>'): '<value>', ...}
#
# Example:
# {('NEXUS_SWITCH', '1.1.1.1', 'username'): 'admin',
#  ('NEXUS_SWITCH', '1.1.1.1', 'password'): 'mySecretPassword',
#  ('NEXUS_SWITCH', '1.1.1.1', 'compute1'): '1/1', ...}
#
device_dictionary = {}


class CiscoConfigOptions():
    """Cisco Configuration Options Class."""

    def __init__(self):
        self._create_device_dictionary()

    def _create_device_dictionary(self):
        """
        Create the device dictionary from the cisco_plugins.ini
        device supported sections. Ex. NEXUS_SWITCH, N1KV.
        """
        for parsed_file in cfg.CONF._cparser.parsed:
            for parsed_item in parsed_file.keys():
                dev_id, sep, dev_ip = parsed_item.partition(':')
                if dev_id == 'NEXUS_SWITCH' or dev_id == 'N1KV':
                    for dev_key, value in parsed_file[parsed_item].items():
                        device_dictionary[dev_id, dev_ip, dev_key] = value[0]


def get_device_dictionary():
    return device_dictionary
