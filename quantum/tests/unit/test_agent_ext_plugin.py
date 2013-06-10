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

import copy
import time

from oslo.config import cfg
from webob import exc

from quantum.api.v2 import attributes
from quantum.common import constants
from quantum.common.test_lib import test_config
from quantum.common import topics
from quantum import context
from quantum.db import agents_db
from quantum.db import db_base_plugin_v2
from quantum.extensions import agent
from quantum.openstack.common import log as logging
from quantum.openstack.common import timeutils
from quantum.openstack.common import uuidutils
from quantum.tests.unit import test_api_v2
from quantum.tests.unit import test_db_plugin


LOG = logging.getLogger(__name__)

_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path
L3_HOSTA = 'hosta'
DHCP_HOSTA = 'hosta'
L3_HOSTB = 'hostb'
DHCP_HOSTC = 'hostc'
DHCP_HOST1 = 'host1'


class AgentTestExtensionManager(object):

    def get_resources(self):
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            agent.RESOURCE_ATTRIBUTE_MAP)
        return agent.Agent.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


# This plugin class is just for testing
class TestAgentPlugin(db_base_plugin_v2.QuantumDbPluginV2,
                      agents_db.AgentDbMixin):
    supported_extension_aliases = ["agent"]


class AgentDBTestMixIn(object):

    def _list_agents(self, expected_res_status=None,
                     quantum_context=None,
                     query_string=None):
        agent_res = self._list('agents',
                               quantum_context=quantum_context,
                               query_params=query_string)
        if expected_res_status:
            self.assertEqual(agent_res.status_int, expected_res_status)
        return agent_res

    def _register_agent_states(self):
        """Register two L3 agents and two DHCP agents."""
        l3_hosta = {
            'binary': 'quantum-l3-agent',
            'host': L3_HOSTA,
            'topic': topics.L3_AGENT,
            'configurations': {'use_namespaces': True,
                               'router_id': None,
                               'handle_internal_only_routers':
                               True,
                               'gateway_external_network_id':
                               None,
                               'interface_driver': 'interface_driver',
                               },
            'agent_type': constants.AGENT_TYPE_L3}
        l3_hostb = copy.deepcopy(l3_hosta)
        l3_hostb['host'] = L3_HOSTB
        dhcp_hosta = {
            'binary': 'quantum-dhcp-agent',
            'host': DHCP_HOSTA,
            'topic': 'DHCP_AGENT',
            'configurations': {'dhcp_driver': 'dhcp_driver',
                               'use_namespaces': True,
                               },
            'agent_type': constants.AGENT_TYPE_DHCP}
        dhcp_hostc = copy.deepcopy(dhcp_hosta)
        dhcp_hostc['host'] = DHCP_HOSTC
        callback = agents_db.AgentExtRpcCallback()
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': l3_hosta},
                              time=timeutils.strtime())
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': l3_hostb},
                              time=timeutils.strtime())
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': dhcp_hosta},
                              time=timeutils.strtime())
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': dhcp_hostc},
                              time=timeutils.strtime())
        return [l3_hosta, l3_hostb, dhcp_hosta, dhcp_hostc]

    def _register_one_dhcp_agent(self):
        """Register one DHCP agent."""
        dhcp_host = {
            'binary': 'quantum-dhcp-agent',
            'host': DHCP_HOST1,
            'topic': 'DHCP_AGENT',
            'configurations': {'dhcp_driver': 'dhcp_driver',
                               'use_namespaces': True,
                               },
            'agent_type': constants.AGENT_TYPE_DHCP}
        callback = agents_db.AgentExtRpcCallback()
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': dhcp_host},
                              time=timeutils.strtime())
        return [dhcp_host]


class AgentDBTestCase(AgentDBTestMixIn,
                      test_db_plugin.QuantumDbPluginV2TestCase):
    fmt = 'json'

    def setUp(self):
        self.adminContext = context.get_admin_context()
        test_config['plugin_name_v2'] = (
            'quantum.tests.unit.test_agent_ext_plugin.TestAgentPlugin')
        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        # Save the original RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()
        ext_mgr = AgentTestExtensionManager()
        test_config['extension_manager'] = ext_mgr
        self.addCleanup(self.restore_resource_attribute_map)
        self.addCleanup(cfg.CONF.reset)
        super(AgentDBTestCase, self).setUp()

    def restore_resource_attribute_map(self):
        # Restore the originak RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def test_create_agent(self):
        data = {'agent': {}}
        _req = self.new_create_request('agents', data, self.fmt)
        _req.environ['quantum.context'] = context.Context(
            '', 'tenant_id')
        res = _req.get_response(self.ext_api)
        self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

    def test_list_agent(self):
        agents = self._register_agent_states()
        res = self._list('agents')
        for agent in res['agents']:
            if (agent['host'] == DHCP_HOSTA and
                agent['agent_type'] == constants.AGENT_TYPE_DHCP):
                self.assertEqual(
                    'dhcp_driver',
                    agent['configurations']['dhcp_driver'])
                break
        self.assertEqual(len(agents), len(res['agents']))

    def test_show_agent(self):
        self._register_agent_states()
        agents = self._list_agents(
            query_string='binary=quantum-l3-agent')
        self.assertEqual(2, len(agents['agents']))
        agent = self._show('agents', agents['agents'][0]['id'])
        self.assertEqual('quantum-l3-agent', agent['agent']['binary'])

    def test_update_agent(self):
        self._register_agent_states()
        agents = self._list_agents(
            query_string='binary=quantum-l3-agent&host=' + L3_HOSTB)
        self.assertEqual(1, len(agents['agents']))
        com_id = agents['agents'][0]['id']
        agent = self._show('agents', com_id)
        new_agent = {}
        new_agent['agent'] = {}
        new_agent['agent']['admin_state_up'] = False
        new_agent['agent']['description'] = 'description'
        self._update('agents', com_id, new_agent)
        agent = self._show('agents', com_id)
        self.assertFalse(agent['agent']['admin_state_up'])
        self.assertEqual('description', agent['agent']['description'])

    def test_dead_agent(self):
        cfg.CONF.set_override('agent_down_time', 1)
        self._register_agent_states()
        time.sleep(1.5)
        agents = self._list_agents(
            query_string='binary=quantum-l3-agent&host=' + L3_HOSTB)
        self.assertFalse(agents['agents'][0]['alive'])


class AgentDBTestCaseXML(AgentDBTestCase):
    fmt = 'xml'
