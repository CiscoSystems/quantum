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
# @author: Bob Melander, Cisco Systems, Inc.

from oslo.config import cfg

from quantum.common import constants
from quantum.common import utils
from quantum import context as quantum_context
from quantum import manager
from quantum.openstack.common import jsonutils
from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class L3CfgRpcCallbackMixin(object):
    """A mix-in that enable L3 cfg agent rpc support in
    plugin implementations.
    """

    def cfg_sync_routers(self, context, **kwargs):
        """Sync routers according to filters to a specific cfg agent.

        @param context: contain user information
        @param kwargs: host, or router_id
        @return: a list of routers
                 with their interfaces and floating_ips
        """
        router_id = kwargs.get('router_id')
        host = kwargs.get('host')
        context = quantum_context.get_admin_context()
        plugin = manager.QuantumManager.get_plugin()
        if utils.is_extension_supported(
                plugin, constants.AGENT_SCHEDULER_EXT_ALIAS):
            if cfg.CONF.router_auto_schedule:
                plugin.auto_schedule_hosting_entities_on_cfg_agent(context,
                                                                   host,
                                                                   router_id)
            routers = plugin.list_active_sync_routers_on_active_l3_cfg_agent(
                context, host, router_id)
        else:
            routers = {}
        LOG.debug(_("Routers returned to l3 cfg agent:\n %s"),
                  jsonutils.dumps(routers, indent=5))
        return routers

    #TODO(bob-melander): Check with Hareesh if we need this function
    def get_external_network_id(self, context, **kwargs):
        """Get one external network id for l3 cfg agent.

        l3 cfg agent expects only on external network when it performs
        this query.
        """
        context = quantum_context.get_admin_context()
        plugin = manager.QuantumManager.get_plugin()
        net_id = plugin.get_external_network_id(context)
        LOG.debug(_("External network ID returned to l3 cfg agent: %s"),
                  net_id)
        return net_id