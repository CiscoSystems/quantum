# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Cisco Systems, Inc.  All rights reserved.
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
# @author: Arvind Somya, Cisco Systems, Inc.
# @author: Kyle Mestery, Cisco Systems, Inc.

from oslo.config import cfg

from quantum.agent.common import config

DEFAULT_TUNNEL_RANGES = '5000:10000'

odl_opts = [
    cfg.StrOpt('controllers',
               help=_("List of controller uri's")),
    cfg.StrOpt('integration_bridge', default='br-int',
               help=_("Integration bridge to use")),
    cfg.StrOpt('network_vlan_ranges',
               help=_("Range of VLAN Ids")),
    cfg.IntOpt('ovsdb_port', default=6634,
               help=_("OVSDB port to connect to")),
    cfg.StrOpt('tenant_network_type',
               help=_("Type of tenant network: vlan | gre")),
    cfg.StrOpt('tunnel_bridge', default='br-tun',
               help=_("Tunnel bridge to use")),
    cfg.StrOpt('int_peer_patch_port', default='patch-tun',
               help=_("Peer patch port in integration bridge for tunnel "
                      "bridge")),
    cfg.StrOpt('tun_peer_patch_port', default='patch-int',
               help=_("Peer patch port in tunnel bridge for integration "
                      "bridge")),
    cfg.ListOpt('tunnel_id_ranges',
                default=DEFAULT_TUNNEL_RANGES,
                help=_("List of <tun_min>:<tun_max>")),
    cfg.StrOpt('physical_bridge',
               default='int-br-eth1',
               help=_("Interface Id of the veth interface on the bridge"))
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
]

cfg.CONF.register_opts(odl_opts, "ODL")
cfg.CONF.register_opts(agent_opts, "AGENT")
config.register_agent_state_opts_helper(cfg.CONF)
config.register_root_helper(cfg.CONF)
