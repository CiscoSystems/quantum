from oslo.config import cfg

from quantum.agent.common import config
from quantum import scheduler

DEFAULT_TUNNEL_RANGES='5000:10000'

odl_opts = [
    cfg.StrOpt('controllers',
                help=_("List of controller uri's")),
    cfg.BoolOpt('enable_tunneling', default=False,
                help=_("Enable tunneling support")),
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
