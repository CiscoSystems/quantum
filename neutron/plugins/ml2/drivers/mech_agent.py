# Copyright (c) 2013 OpenStack Foundation
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

from abc import ABCMeta, abstractmethod

from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api

LOG = log.getLogger(__name__)


class AgentMechanismDriverBase(api.MechanismDriver):
    """Base class for drivers that attach to networks using an L2 agent.

    The AgentMechanismDriverBase provides common code for mechanism
    drivers that integrate the ml2 plugin with L2 agents. Port binding
    with this driver requires the driver's associated agent to be
    running on the port's host, and that agent to have connectivity to
    at least one segment of the port's network.

    MechanismDrivers using this base class must pass the agent type
    and VIF type constants to __init__(), and must implement
    check_segment_for_agent().
    """

    __metaclass__ = ABCMeta

    def __init__(self, agent_type, vif_type, cap_port_filter):
        """Initialize base class for specific L2 agent type.

        :param agent_type: Constant identifying agent type in agents_db
        :param vif_type: Value for binding:vif_type to when bound
        """
        self.agent_type = agent_type
        self.vif_type = vif_type
        self.cap_port_filter = cap_port_filter

    def initialize(self):
        pass

    def bind_port(self, context):
        LOG.debug(_("Attempting to bind port %(port)s on "
                    "network %(network)s"),
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        for agent in context.host_agents(self.agent_type):
            LOG.debug(_("Checking agent: %s"), agent)
            if agent['alive']:
                for segment in context.network.network_segments:
                    if self.check_segment_for_agent(segment, agent):
                        context.set_binding(segment[api.ID],
                                            self.vif_type,
                                            self.cap_port_filter)
                        LOG.debug(_("Bound using segment: %s"), segment)
                        return
            else:
                LOG.warning(_("Attempting to bind with dead agent: %s"),
                            agent)

    def validate_port_binding(self, context):
        LOG.debug(_("Validating binding for port %(port)s on "
                    "network %(network)s"),
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        for agent in context.host_agents(self.agent_type):
            LOG.debug(_("Checking agent: %s"), agent)
            if agent['alive'] and self.check_segment_for_agent(
                context.bound_segment, agent):
                LOG.debug(_("Binding valid"))
                return True
        LOG.warning(_("Binding invalid for port: %s"), context.current)
        return False

    def unbind_port(self, context):
        LOG.debug(_("Unbinding port %(port)s on "
                    "network %(network)s"),
                  {'port': context.current['id'],
                   'network': context.network.current['id']})

    @abstractmethod
    def check_segment_for_agent(self, segment, agent):
        """Check if segment can be bound for agent.

        :param segment: segment dictionary describing segment to bind
        :param agent: agents_db entry describing agent to bind
        :returns: True iff segment can be bound for agent

        Called inside transaction during bind_port() and
        validate_port_binding() so that derived MechanismDrivers can
        use agent_db data along with built-in knowledge of the
        corresponding agent's capabilities to determine whether or not
        the specified network segment can be bound for the agent.
        """
