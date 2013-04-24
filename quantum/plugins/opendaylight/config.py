from oslo.config import cfg

from quantum.agent.common import config
from quantum import scheduler

odl_opts = [
    cfg.StrOpt('controllers',
                help=_("List of controller uri's")),
    cfg.StrOpt('network_vlan_ranges',
                help=_("Range of VLAN Ids")),
    cfg.StrOpt('network_tunnel_ranges',
                help=_("List of tunnel ids")),
    cfg.StrOpt('tenant_network_type',
                help=_("Type of tenant network: vlan | gre")),
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
