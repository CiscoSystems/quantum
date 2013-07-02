# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 OpenStack Foundation.
# All Rights Reserved.
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

import random

from sqlalchemy.orm import exc
from sqlalchemy.sql import exists

from quantum.common import constants
from quantum.db import l3_db
from quantum.db import agents_db
from quantum.db import agentschedulers_db
from quantum.openstack.common import log as logging
from quantum.plugins.cisco.l3.common import constants as cl3_constants
from quantum.plugins.cisco.l3.db import l3_router_appliance_db as l3_ra_db


LOG = logging.getLogger(__name__)


class L3AgentCompositeScheduler(object):
    """A composite scheduler that schedules a) network namespace based
    routers to l3 agents, as well as, b) hosting entities to l3 cfg agents.
    In both cases the scheduling is a simple random selection among
    qualified candidates."""

    def auto_schedule_hosting_entities_on_cfg_agent(self, context, agent_host,
                                                    router_id):
        """Schedules unassociated hosting entities to the l3 cfg agent
        running on <agent_host>. If <router_id> is given, then only
        hosting entity hosting the router with that id is scheduled (if
        it is unassociated). If no <router_id> is given, then all
        unassociated hosting entities are scheduled.
        """
        with context.session.begin(subtransactions=True):
            # Check if there is a valid l3 cfg agent on the host
            query = context.session.query(agents_db.Agent)
            query = query.filter(agents_db.Agent.agent_type ==
                                 cl3_constants.AGENT_TYPE_L3_CFG,
                                 agents_db.Agent.host == agent_host,
                                 agents_db.Agent.admin_state_up == True)
            try:
                l3_cfg_agent = query.one()
            except (exc.MultipleResultsFound, exc.NoResultFound):
                LOG.debug(_('No enabled L3 cfg agent on host %s'),
                          agent_host)
                return False
            if agents_db.AgentDbMixin.is_agent_down(
                l3_cfg_agent.heartbeat_timestamp):
                LOG.warn(_('L3 cfg agent %s is not alive'), l3_cfg_agent.id)

            #mysql> SELECT * FROM hostingentities
            # JOIN routerhostingentitybindings ON id=hosting_entity_id
            # WHERE l3_cfg_agent_id is NULL AND
            # routerhostingentitybindings.router_id = 'r_id3';

            query = context.session.query(l3_ra_db.HostingEntity)
            if router_id:
                query = query.join(l3_ra_db.RouterHostingEntityBinding)
                query = query.filter(
                    l3_ra_db.RouterHostingEntityBinding.router_id == router_id)
            query = query.filter(
                l3_ra_db.HostingEntity.l3_cfg_agent_id == None)
            for he in query:
                he.l3_cfg_agent = l3_cfg_agent
                context.session.add(he)
            return True

    def auto_schedule_routers(self, plugin, context, host, router_id):
        """Schedule non-hosted network namespace-based routers to L3 Agent
        running on host. If router_id is given, only this router is scheduled
        if it is not hosted yet. Don't schedule the routers which are hosted
        already by active l3 agents.
        """
        with context.session.begin(subtransactions=True):
            # query if we have valid l3 agent on the host
            query = context.session.query(agents_db.Agent)
            query = query.filter(agents_db.Agent.agent_type ==
                                 constants.AGENT_TYPE_L3,
                                 agents_db.Agent.host == host,
                                 agents_db.Agent.admin_state_up == True)
            try:
                l3_agent = query.one()
            except (exc.MultipleResultsFound, exc.NoResultFound):
                LOG.debug(_('No enabled L3 agent on host %s'),
                          host)
                return False
            if agents_db.AgentDbMixin.is_agent_down(
                l3_agent.heartbeat_timestamp):
                LOG.warn(_('L3 agent %s is not active'), l3_agent.id)
            # Only network namespace based routers should be scheduled here
            router_type = (cl3_constants.NAMESPACE_ROUTER_TYPE
                           if router_id is None
                           else plugin.get_router_type(context, router_id))
            if router_type != cl3_constants.NAMESPACE_ROUTER_TYPE:
                LOG.debug(_('Router %(router_id)s is of type %(router_type)s'
                            ' which is not hosted by l3 agents'),
                            {'router_id': router_id,
                             'router_type': router_type})
                return False
            # check if the specified router is hosted
            if router_id:
                l3_agents = plugin.get_l3_agents_hosting_routers(
                    context, [router_id], admin_state_up=True)
                if l3_agents:
                    LOG.debug(_('Router %(router_id)s has already been hosted'
                                ' by L3 agent %(agent_id)s'),
                              {'router_id': router_id,
                               'agent_id': l3_agents[0]['id']})
                    return False

            # get the router ids
            if router_id:
                router_ids = [(router_id,)]
            else:
                # get all routers that are not hosted
                #TODO(gongysh) consider the disabled agent's router
                stmt = ~exists().where(
                    l3_db.Router.id ==
                    agentschedulers_db.RouterL3AgentBinding.router_id)
                # Modified to only include routers of network namespace type
                query = context.session.query(l3_db.Router.id)
                query = query.join(l3_ra_db.RouterHostingEntityBinding)
                router_ids = query.filter(
                    l3_ra_db.RouterHostingEntityBinding.router_type ==
                    cl3_constants.NAMESPACE_ROUTER_TYPE,
                    stmt).all()
            if not router_ids:
                LOG.debug(_('No non-hosted routers'))
                return False

            # check if the configuration of l3 agent is compatible
            # with the router
            router_ids = [router_id_[0] for router_id_ in router_ids]
            routers = plugin.get_routers(context, filters={'id': router_ids})
            to_removed_ids = []
            for router in routers:
                candidates = plugin.get_l3_agent_candidates(router, [l3_agent])
                if not candidates:
                    to_removed_ids.append(router['id'])
            router_ids = list(set(router_ids) - set(to_removed_ids))
            if not router_ids:
                LOG.warn(_('No routers compatible with L3 agent configuration'
                           ' on host %s'), host)
                return False

            # binding
            for router_id in router_ids:
                binding = agentschedulers_db.RouterL3AgentBinding()
                binding.l3_agent = l3_agent
                binding.router_id = router_id
                binding.default = True
                context.session.add(binding)
        return True

    def schedule(self, plugin, context, sync_router):
        if sync_router['router_type'] == cl3_constants.NAMESPACE_ROUTER_TYPE:
            # Do the traditional Quantum router scheduling
            return self.schedule_namespace_router(plugin, context, sync_router)
        else:
            # Schedule the hosting entity to a l3 cfg agent
            return self.schedule_hosting_entity_on_l3_cfg_agent(
                plugin, context, sync_router['hosting_entity']['id'])

    def schedule_hosting_entity_on_l3_cfg_agent(self, plugin, context, id):
        """Selects l3 cfg agent that will configure hosting entity."""
        with context.session.begin(subtransactions=True):
            he_db = plugin.get_hosting_entities(context, [id])
            if not he_db:
                LOG.debug(_('DB inconsistency: Hosting entity %s could '
                            'not be found'), id)
                return
            if he_db[0].l3_cfg_agent:
                LOG.debug(_('Hosting entity %(he_id)s has already been '
                            'assigned to L3 cfg agent %(agent_id)s'),
                          {'he_id': id,
                           'agent_id': he_db[0].l3_cfg_agent['id']})
                return

            active_l3_cfg_agents = plugin.get_l3_cfg_agents(context,
                                                            active=True)
            if not active_l3_cfg_agents:
                LOG.warn(_('There are no active L3CfgAgents'))
                # No worries, once a l3 cfg agent is started and
                # announces itself any "dangling" hosting entities
                # will be scheduled to it.
                return
            chosen_agent = random.choice(active_l3_cfg_agents)
            he_db[0].l3_cfg_agent = chosen_agent
            context.session.add(he_db[0])
            return chosen_agent

    def schedule_namespace_router(self, plugin, context, sync_router):
        """Schedule the router to an active L3 agent if there
        is no enable L3 agent hosting it.
        """
        with context.session.begin(subtransactions=True):
            # allow one router is hosted by just
            # one enabled l3 agent hosting since active is just a
            # timing problem. Non-active l3 agent can return to
            # active any time
            l3_agents = plugin.get_l3_agents_hosting_routers(
                context, [sync_router['id']], admin_state_up=True)
            if l3_agents:
                LOG.debug(_('Router %(router_id)s has already been hosted'
                            ' by L3 agent %(agent_id)s'),
                          {'router_id': sync_router['id'],
                           'agent_id': l3_agents[0]['id']})
                return

            active_l3_agents = plugin.get_l3_agents(context, active=True)
            if not active_l3_agents:
                LOG.warn(_('No active L3 agents'))
                return
            candidates = plugin.get_l3_agent_candidates(sync_router,
                                                        active_l3_agents)
            if not candidates:
                LOG.warn(_('No L3 agents can host the router %s'),
                         sync_router['id'])
                return

            chosen_agent = random.choice(candidates)
            binding = agentschedulers_db.RouterL3AgentBinding()
            binding.l3_agent = chosen_agent
            binding.router_id = sync_router['id']
            context.session.add(binding)
            LOG.debug(_('Router %(router_id)s is scheduled to '
                        'L3 agent %(agent_id)s'),
                      {'router_id': sync_router['id'],
                       'agent_id': chosen_agent['id']})
            return chosen_agent
