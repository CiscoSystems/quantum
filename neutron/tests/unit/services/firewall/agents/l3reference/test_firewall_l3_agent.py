# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013 OpenStack Foundation
# All Rights Reserved.
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
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com, Big Switch Networks, Inc.
# @author: Sridar Kandaswamy, skandasw@cisco.com, Cisco Systems, Inc.
# @author: Dan Florea, dflorea@cisco.com, Cisco Systems, Inc.

import contextlib
import mock
from oslo.config import cfg

from neutron.agent.common import config as agent_config
from neutron.common import config as base_config
from neutron import context
from neutron.plugins.common import constants
from neutron.services.firewall.agents.l3reference import firewall_l3_agent
from neutron.tests import base


class FWaasHelper(object):
    def __init__(self, host):
        pass


class FWaasAgent(firewall_l3_agent.FWaaSL3AgentRpcCallback, FWaasHelper):
    def __init__(self, conf=None):
        super(FWaasAgent, self).__init__(conf)


class TestFwaasL3AgentRpcCallback(base.BaseTestCase):
    def setUp(self):
        super(TestFwaasL3AgentRpcCallback, self).setUp()
        self.addCleanup(mock.patch.stopall)

        self.conf = cfg.ConfigOpts()
        self.conf.register_opts(base_config.core_opts)
        agent_config.register_root_helper(self.conf)
        self.conf.root_helper = 'sudo'
        self.api = FWaasAgent(self.conf)

    def test_create_firewall(self):
        fake_firewall = {'id': 0}
        with mock.patch.object(
            self.api,
            '_invoke_driver_for_plugin_api'
        ) as mock_driver:
            self.assertEqual(
                self.api.create_firewall(
                    mock.sentinel.context,
                    fake_firewall,
                    'host'),
                mock_driver.return_value)

    def test_update_firewall(self):
        fake_firewall = {'id': 0}
        with mock.patch.object(
            self.api,
            '_invoke_driver_for_plugin_api'
        ) as mock_driver:
            self.assertEqual(
                self.api.update_firewall(
                    mock.sentinel.context,
                    fake_firewall,
                    'host'),
                mock_driver.return_value)

    def test_delete_firewall(self):
        fake_firewall = {'id': 0}
        with mock.patch.object(
            self.api,
            '_invoke_driver_for_plugin_api'
        ) as mock_driver:
            self.assertEqual(
                self.api.delete_firewall(
                    mock.sentinel.context,
                    fake_firewall,
                    'host'),
                mock_driver.return_value)

    def test_invoke_driver_for_plugin_api(self):
        fake_firewall = {'id': 0, 'tenant_id': 1}
        self.api.plugin_rpc = mock.Mock()
        with contextlib.nested(
            mock.patch.object(self.api.plugin_rpc, 'get_routers'),
            mock.patch.object(self.api, '_get_router_info_list_for_tenant'),
            mock.patch.object(self.api.fwaas_driver, 'create_firewall'),
            mock.patch.object(self.api.fwplugin_rpc, 'set_firewall_status')
        ) as (
            mock_get_routers,
            mock_get_router_info_list_for_tenant,
            mock_driver_create_firewall,
            mock_set_firewall_status):

            mock_driver_create_firewall.return_value = True
            self.api.create_firewall(
                context=mock.sentinel.context,
                firewall=fake_firewall, host='host')

            mock_get_routers.assert_called_once_with(
                mock.sentinel.context)

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                mock_get_routers.return_value, fake_firewall['tenant_id'])

            mock_set_firewall_status.assert_called_once_with(
                mock.sentinel.context,
                fake_firewall['id'],
                'ACTIVE')

    def test_invoke_driver_for_plugin_api_delete(self):
        fake_firewall = {'id': 0, 'tenant_id': 1}
        self.api.plugin_rpc = mock.Mock()
        with contextlib.nested(
            mock.patch.object(self.api.plugin_rpc, 'get_routers'),
            mock.patch.object(self.api, '_get_router_info_list_for_tenant'),
            mock.patch.object(self.api.fwaas_driver, 'delete_firewall'),
            mock.patch.object(self.api.fwplugin_rpc, 'firewall_deleted')
        ) as (
            mock_get_routers,
            mock_get_router_info_list_for_tenant,
            mock_driver_delete_firewall,
            mock_firewall_deleted):

            mock_driver_delete_firewall.return_value = True
            self.api.delete_firewall(
                context=mock.sentinel.context,
                firewall=fake_firewall, host='host')

            mock_get_routers.assert_called_once_with(
                mock.sentinel.context)

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                mock_get_routers.return_value, fake_firewall['tenant_id'])

            mock_firewall_deleted.assert_called_once_with(
                mock.sentinel.context,
                fake_firewall['id'])

    def test_process_router_add_fw_update(self):
        fake_firewall_list = [{'id': 0, 'tenant_id': 1,
                               'status': constants.PENDING_UPDATE}]
        fake_router = {'id': 1111, 'tenant_id': 2}
        self.api.plugin_rpc = mock.Mock()
        ri = mock.Mock()
        ri.router = fake_router
        routers = [ri.router]
        with contextlib.nested(
            mock.patch.object(self.api.plugin_rpc, 'get_routers'),
            mock.patch.object(self.api, '_get_router_info_list_for_tenant'),
            mock.patch.object(self.api.fwaas_driver, 'update_firewall'),
            mock.patch.object(self.api.fwplugin_rpc, 'set_firewall_status'),
            mock.patch.object(self.api.fwplugin_rpc,
                              'get_firewalls_for_tenant'),
            mock.patch.object(context, 'Context')
        ) as (
            mock_get_routers,
            mock_get_router_info_list_for_tenant,
            mock_driver_update_firewall,
            mock_set_firewall_status,
            mock_get_firewalls_for_tenant,
            mock_Context):

            mock_driver_update_firewall.return_value = True
            ctx = mock.sentinel.context
            mock_Context.return_value = ctx
            mock_get_router_info_list_for_tenant.return_value = routers
            mock_get_firewalls_for_tenant.return_value = fake_firewall_list

            self.api._process_router_add(ri)
            mock_get_router_info_list_for_tenant.assert_called_with(
                routers,
                ri.router['tenant_id'])
            mock_get_firewalls_for_tenant.assert_called_once_with(ctx)
            mock_driver_update_firewall.assert_called_once(
                routers,
                fake_firewall_list[0])

            mock_set_firewall_status.assert_called_once_with(
                ctx,
                fake_firewall_list[0]['id'],
                constants.ACTIVE)

    def test_process_router_add_fw_delete(self):
        fake_firewall_list = [{'id': 0, 'tenant_id': 1,
                               'status': constants.PENDING_DELETE}]
        fake_router = {'id': 1111, 'tenant_id': 2}
        self.api.plugin_rpc = mock.Mock()
        ri = mock.Mock()
        ri.router = fake_router
        routers = [ri.router]
        with contextlib.nested(
            mock.patch.object(self.api.plugin_rpc, 'get_routers'),
            mock.patch.object(self.api, '_get_router_info_list_for_tenant'),
            mock.patch.object(self.api.fwaas_driver, 'delete_firewall'),
            mock.patch.object(self.api.fwplugin_rpc, 'firewall_deleted'),
            mock.patch.object(self.api.fwplugin_rpc,
                              'get_firewalls_for_tenant'),
            mock.patch.object(context, 'Context')
        ) as (
            mock_get_routers,
            mock_get_router_info_list_for_tenant,
            mock_driver_delete_firewall,
            mock_firewall_deleted,
            mock_get_firewalls_for_tenant,
            mock_Context):

            mock_driver_delete_firewall.return_value = True
            ctx = mock.sentinel.context
            mock_Context.return_value = ctx
            mock_get_router_info_list_for_tenant.return_value = routers
            mock_get_firewalls_for_tenant.return_value = fake_firewall_list

            self.api._process_router_add(ri)
            mock_get_router_info_list_for_tenant.assert_called_with(
                routers,
                ri.router['tenant_id'])
            mock_get_firewalls_for_tenant.assert_called_once_with(ctx)
            mock_driver_delete_firewall.assert_called_once(
                routers,
                fake_firewall_list[0])

            mock_firewall_deleted.assert_called_once_with(
                ctx,
                fake_firewall_list[0]['id'])
