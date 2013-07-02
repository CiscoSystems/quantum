# Copyright (c) 2013 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from quantum.api.rpc.agentnotifiers import l3_rpc_agent_api
from quantum.common import constants
from quantum.common import topics
from quantum.common import utils
from quantum import manager
from quantum.openstack.common import log as logging
from quantum.openstack.common.rpc import proxy
from quantum.plugins.cisco.l3.common import l3_rpc_agent_api_noop
from quantum.plugins.cisco.l3.common import constants as cl3_constants


LOG = logging.getLogger(__name__)


AGENT_TYPE = {topics.L3_AGENT:" ",
              cl3_constants.L3_CFG_AGENT: " cfg "}

class L3JointAgentNotifyAPI(proxy.RpcProxy):
    """API for plugin to notify L3 cfg agent and L3 agent."""
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=topics.L3_AGENT):
        super(L3JointAgentNotifyAPI, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

    def _notification_host(self, context, method, payload, host,
                           topic=topics.L3_AGENT):
        """Notify the agent that is hosting the router."""
        LOG.debug(_('Notify agent at %(host)s the message '
                    '%(method)s'), {'host': host,
                                    'method': method})
        self.cast(context,
                  self.make_msg(method, payload=payload),
                  topic='%s.%s' % (topic, host))

    def _agent_notification(self, context, method, routers,
                            operation, data):
        """Notify changed routers to the l3 configuration agents
        of their hosting entities or the routers' hosting l3 agents.

        Adjust routers according to l3 agents' role and
        related dhcp agents.
        Notify dhcp agent to get right subnet's gateway ips.
        """
        adminContext = context.is_admin and context or context.elevated()
        plugin = manager.QuantumManager.get_plugin()
        for router in routers:
            if router['router_type'] == cl3_constants.NAMESPACE_ROUTER_TYPE:
                agents = plugin.get_l3_agents_hosting_routers(
                    adminContext, [router['id']],
                    admin_state_up=True,
                    active=True)
            elif router['hosting_entity'] is not None:
                agents = plugin.get_l3_cfg_agents_for_hosting_entities(
                    adminContext, [router['hosting_entity']['id']],
                    admin_state_up=True,
                    active=True)
            else:
                agents = []
            for agent in agents:
                LOG.debug(_('Notify l3%(type)sagent at %(topic)s.%(host)s the message '
                            '%(method)s'),
                          {'type': AGENT_TYPE[agent.topic],
                           'topic': agent.topic,
                           'host': agent.host,
                           'method': method})
                self.cast(context,
                          self.make_msg(method, routers=[router]),
                          topic='%s.%s' % (agent.topic, agent.host))

    def _notification(self, context, method, routers, operation, data):
        """Notify all the l3 agents and l3 cfg agents that are
        hosting or configuring the routers, respectively."""
        plugin = manager.QuantumManager.get_plugin()
        if utils.is_extension_supported(
                plugin, constants.AGENT_SCHEDULER_EXT_ALIAS):
            adminContext = (context.is_admin and
                            context or context.elevated())
            # This is where a hosting entity gets scheduled to a
            # l3 cfg agent and where network namespace based routers
            # get scheduled to a l3 agent.
            plugin.schedule_routers(adminContext, routers)
            self._agent_notification(
                context, method, routers, operation, data)
        else:
            self.fanout_cast(
                context, self.make_msg(method,
                                       routers=routers),
                topic=topics.L3_AGENT)

    def _notification_fanout(self, context, method, router_id):
        """Fanout the deleted router to all L3 agents.
        """
        LOG.debug(_('Fanout notify agent at %(topic)s the message '
                    '%(method)s on router %(router_id)s'),
                  {'topic': topics.DHCP_AGENT,
                   'method': method,
                   'router_id': router_id})
        self.fanout_cast(context,
                         self.make_msg(method, router_id=router_id),
                         topic=topics.L3_AGENT)

    def agent_updated(self, context, admin_state_up, host):
        #TODO(bob-melander): Ensure correct topic is used for l3 cfg agent
        self._notification_host(context, 'agent_updated',
                                {'admin_state_up': admin_state_up},
                                host)

    def router_deleted(self, context, router):
        if router['router_type'] == cl3_constants.NAMESPACE_ROUTER_TYPE:
            self._notification_fanout(context, 'router_deleted', router['id'])
        else:
            self._agent_notification(context,'router_deleted',[router],
                                     operation=None, data=None)

    def routers_updated(self, context, routers, operation=None, data=None):
        if routers:
            self._notification(context, 'routers_updated', routers,
                               operation, data)

    def router_removed_from_agent(self, context, router_id, host):
        self._notification_host(context, 'router_removed_from_agent',
                                {'router_id': router_id}, host,
                                topic=topics.L3_AGENT)

    def router_added_to_agent(self, context, routers, host):
        self._notification_host(context, 'router_added_to_agent',
                                routers, host,
                                topic=topics.L3_AGENT)

    def router_removed_from_hosting_entity(self, context, router_id, host):
        self._notification_host(context, 'router_removed_from_hosting_entity',
                                {'router_id': router_id}, host,
                                topic=cl3_constants.L3_CFG_AGENT)

    def router_added_to_hosting_entity(self, context, routers, host):
        self._notification_host(context, 'router_added_to_hosting_entity',
                                routers, host,
                                topic=cl3_constants.L3_CFG_AGENT)

L3JointAgentNotify = L3JointAgentNotifyAPI()

# Monkey patch
L3AgentNotify = l3_rpc_agent_api.L3AgentNotify
l3_rpc_agent_api.L3AgentNotify = l3_rpc_agent_api_noop.L3AgentNotifyNoOp