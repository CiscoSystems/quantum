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

from quantum.common import topics
from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)


# TODO(bob-melander): This class is just a temporary arrangement to make
# rebasing trivial. We monkey patch so that this class is used instead of
# the L3AgentNotifyAPI proper. The latter is instead called by our
# composite agent notifier class.
# For the code that we upstream a better approach is to add a parameter,
# notify_agents=True, to all functions in L3_NAT_db_mixin (and derived
# classes) that determines if agent notifications will be sent or not.
class L3AgentNotifyAPINoOp(object):
    """API for plugin to notify L3 agent but without actions."""
    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=topics.L3_AGENT):
        pass

    def _notification_host(self, context, method, payload, host):
        """Notify the agent that is hosting the router."""
        pass

    def _agent_notification(self, context, method, routers,
                            operation, data):
        """Notify changed routers to hosting l3 agents.

        Adjust routers according to l3 agents' role and
        related dhcp agents.
        Notify dhcp agent to get right subnet's gateway ips.
        """
        pass

    def _notification(self, context, method, routers, operation, data):
        """Notify all the agents that are hosting the routers."""
        pass

    def _notification_fanout(self, context, method, router_id):
        """Fanout the deleted router to all L3 agents."""
        pass

    def agent_updated(self, context, admin_state_up, host):
        pass

    def router_deleted(self, context, router_id):
        pass

    def routers_updated(self, context, routers, operation=None, data=None):
        pass

    def router_removed_from_agent(self, context, router_id, host):
        pass

    def router_added_to_agent(self, context, routers, host):
        pass

L3AgentNotifyNoOp = L3AgentNotifyAPINoOp()
