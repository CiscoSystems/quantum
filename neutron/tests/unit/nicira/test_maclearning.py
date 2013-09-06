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

import contextlib
import mock

from oslo.config import cfg

from neutron.api.v2 import attributes
from neutron.common.test_lib import test_config
from neutron import context
from neutron.extensions import agent
from neutron.plugins.nicira.common import sync
from neutron.plugins.nicira.NvpApiClient import NVPVersion
from neutron.tests.unit.nicira import fake_nvpapiclient
from neutron.tests.unit.nicira import get_fake_conf
from neutron.tests.unit.nicira import NVPAPI_NAME
from neutron.tests.unit.nicira import NVPEXT_PATH
from neutron.tests.unit.nicira import PLUGIN_NAME
from neutron.tests.unit.nicira import STUBS_PATH
from neutron.tests.unit import test_db_plugin


class MacLearningExtensionManager(object):

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


class MacLearningDBTestCase(test_db_plugin.NeutronDbPluginV2TestCase):
    fmt = 'json'

    def setUp(self):
        self.adminContext = context.get_admin_context()
        test_config['config_files'] = [get_fake_conf('nvp.ini.full.test')]
        test_config['plugin_name_v2'] = PLUGIN_NAME
        cfg.CONF.set_override('api_extensions_path', NVPEXT_PATH)
        # Save the original RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()
        ext_mgr = MacLearningExtensionManager()
        test_config['extension_manager'] = ext_mgr
        # mock nvp api client
        self.fc = fake_nvpapiclient.FakeClient(STUBS_PATH)
        self.mock_nvpapi = mock.patch(NVPAPI_NAME, autospec=True)
        instance = self.mock_nvpapi.start()
        # Avoid runs of the synchronizer looping call
        patch_sync = mock.patch.object(sync, '_start_loopingcall')
        patch_sync.start()

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        # Emulate tests against NVP 2.x
        instance.return_value.get_nvp_version.return_value = NVPVersion("3.0")
        instance.return_value.request.side_effect = _fake_request
        cfg.CONF.set_override('metadata_mode', None, 'NVP')
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(self.mock_nvpapi.stop)
        self.addCleanup(patch_sync.stop)
        self.addCleanup(self.restore_resource_attribute_map)
        self.addCleanup(cfg.CONF.reset)
        super(MacLearningDBTestCase, self).setUp()

    def restore_resource_attribute_map(self):
        # Restore the original RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def test_create_with_mac_learning(self):
        with self.port(arg_list=('mac_learning_enabled',),
                       mac_learning_enabled=True) as port:
            # Validate create operation response
            self.assertEqual(True, port['port']['mac_learning_enabled'])
            # Verify that db operation successfully set mac learning state
            req = self.new_show_request('ports', port['port']['id'], self.fmt)
            sport = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(True, sport['port']['mac_learning_enabled'])

    def test_create_and_show_port_without_mac_learning(self):
        with self.port() as port:
            req = self.new_show_request('ports', port['port']['id'], self.fmt)
            sport = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertNotIn('mac_learning_enabled', sport['port'])

    def test_update_port_with_mac_learning(self):
        with self.port(arg_list=('mac_learning_enabled',),
                       mac_learning_enabled=False) as port:
            data = {'port': {'mac_learning_enabled': True}}
            req = self.new_update_request('ports', data, port['port']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(True, res['port']['mac_learning_enabled'])

    def test_update_preexisting_port_with_mac_learning(self):
        with self.port() as port:
            req = self.new_show_request('ports', port['port']['id'], self.fmt)
            sport = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertNotIn('mac_learning_enabled', sport['port'])
            data = {'port': {'mac_learning_enabled': True}}
            req = self.new_update_request('ports', data, port['port']['id'])
            # Validate update operation response
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(True, res['port']['mac_learning_enabled'])
            # Verify that db operation successfully updated mac learning state
            req = self.new_show_request('ports', port['port']['id'], self.fmt)
            sport = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(True, sport['port']['mac_learning_enabled'])

    def test_list_ports(self):
        # for this test we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with contextlib.nested(self.port(arg_list=('mac_learning_enabled',),
                                         mac_learning_enabled=True),
                               self.port(arg_list=('mac_learning_enabled',),
                                         mac_learning_enabled=True),
                               self.port(arg_list=('mac_learning_enabled',),
                                         mac_learning_enabled=True)):
            for port in self._list('ports')['ports']:
                self.assertEqual(True, port['mac_learning_enabled'])

    def test_show_port(self):
        with self.port(arg_list=('mac_learning_enabled',),
                       mac_learning_enabled=True) as p:
            port_res = self._show('ports', p['port']['id'])['port']
            self.assertEqual(True, port_res['mac_learning_enabled'])
