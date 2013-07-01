# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Red Hat, Inc.
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
from quantum.plugins.openvswitch.common import constants
from quantum import scheduler


DEFAULT_BRIDGE_MAPPINGS = []
DEFAULT_VLAN_RANGES = []
DEFAULT_TUNNEL_RANGES = []

ovs_opts = [
    cfg.StrOpt('integration_bridge', default='br-int',
               help=_("Integration bridge to use")),
    cfg.BoolOpt('enable_tunneling', default=False,
                help=_("Enable tunneling support")),
    cfg.StrOpt('tunnel_bridge', default='br-tun',
               help=_("Tunnel bridge to use")),
    cfg.StrOpt('int_peer_patch_port', default='patch-tun',
               help=_("Peer patch port in integration bridge for tunnel "
                      "bridge")),
    cfg.StrOpt('tun_peer_patch_port', default='patch-int',
               help=_("Peer patch port in tunnel bridge for integration "
                      "bridge")),
    cfg.StrOpt('local_ip', default='',
               help=_("Local IP address of GRE tunnel endpoints.")),
    cfg.ListOpt('bridge_mappings',
                default=DEFAULT_BRIDGE_MAPPINGS,
                help=_("List of <physical_network>:<bridge>")),
    cfg.StrOpt('tenant_network_type', default='local',
               help=_("Network type for tenant networks "
                      "(local, vlan, gre, vxlan, or none)")),
    cfg.ListOpt('network_vlan_ranges',
                default=DEFAULT_VLAN_RANGES,
                help=_("List of <physical_network>:<vlan_min>:<vlan_max> "
                       "or <physical_network>")),
    cfg.ListOpt('tunnel_id_ranges',
                default=DEFAULT_TUNNEL_RANGES,
                help=_("List of <tun_min>:<tun_max>")),
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
    cfg.StrOpt('tunnel_type', default=None,
               help=_("Network type for agent tunnel networks "
                      "(gre or vxlan)")),
    cfg.IntOpt('vxlan_udp_port', default=constants.VXLAN_UDP_PORT,
               help=_("The UDP port to use for VXLAN tunnels.")),
]


cfg.CONF.register_opts(ovs_opts, "OVS")
cfg.CONF.register_opts(agent_opts, "AGENT")
config.register_agent_state_opts_helper(cfg.CONF)
config.register_root_helper(cfg.CONF)
cfg.CONF.register_opts(scheduler.AGENTS_SCHEDULER_OPTS)
