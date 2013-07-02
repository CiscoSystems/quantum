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

import mock
from oslo.config import cfg
import webtest


from quantum.api import extensions
from quantum.common.test_lib import test_config
from quantum.manager import QuantumManager
from quantum.openstack.common import log as logging
from quantum.openstack.common.notifier import api as notifier_api
from quantum.openstack.common.notifier import test_notifier
from quantum.openstack.common import uuidutils
from quantum.plugins.cisco.l3.db import l3_router_appliance_db
from quantum.tests import base
from quantum.tests.unit import test_api_v2
from quantum.tests.unit import test_extension_extraroute
from quantum.tests.unit import test_l3_plugin

LOG = logging.getLogger(__name__)

#_uuid = uuidutils.generate_uuid
#_get_path = test_api_v2._get_path


# This plugin class is just for testing
class TestL3RouterAppliancePlugin(
    test_extension_extraroute.TestExtraRoutePlugin,
    l3_router_appliance_db.L3_router_appliance_db_mixin):
    pass


class L3RouterApplianceTestCase(test_extension_extraroute.ExtraRouteDBTestCase):

    def setUp(self):
        test_config['plugin_name_v2'] = (
            'quantum.plugins.cisco.l3.tests.unit.'
            'test_l3_router_appliance_plugin.TestL3RouterAppliancePlugin')
        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = test_extension_extraroute.ExtraRouteTestExtensionManager()
        test_config['extension_manager'] = ext_mgr
        #L3NatDBTestCase will overwrite plugin_name_v2,
        #so we don't need to setUp on the class here
        super(test_l3_plugin.L3NatTestCaseBase, self).setUp()

        # Set to None to reload the drivers
        notifier_api._drivers = None
        cfg.CONF.set_override("notification_driver", [test_notifier.__name__])

        self.tenant_id_fcn_p = mock.patch('quantum.plugins.cisco.l3.db.'
                                          'l3_router_appliance_db.'
                                          'L3_router_appliance_db_mixin.'
                                          'l3_tenant_id')
        self.tenant_id_fcn = self.tenant_id_fcn_p.start()
        self.tenant_id_fcn = mock.MagicMock(return_value='L3AdminTenantId')

    def tearDown(self):
        self.tenant_id_fcn_p.stop()
        super(test_l3_plugin.L3NatDBTestCase, self).tearDown()


class L3RouterApplianceTestCaseXML(L3RouterApplianceTestCase):
    fmt = 'xml'


class myTestCase(base.BaseTestCase):
    def setUp(self):
        # Ensure 'stale' patched copies of the plugin are never returned
        QuantumManager._instance = None

        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None
        test_config['plugin_name_v2'] = (
            'quantum.plugins.cisco.l3.tests.unit.'
            'test_l3_router_appliance_plugin.TestL3RouterAppliancePlugin')
        # Update the plugin and extensions path
        cfg.CONF.set_override('core_plugin', test_config['plugin_name_v2'])
        cfg.CONF.set_override('allow_pagination', True)
        cfg.CONF.set_override('allow_sorting', True)
        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = test_extension_extraroute.ExtraRouteTestExtensionManager()
        test_config['extension_manager'] = ext_mgr
        #L3NatDBTestCase will overwrite plugin_name_v2,
        #so we don't need to setUp on the class here
        super(myTestCase, self).setUp()

        # Set to None to reload the drivers
        notifier_api._drivers = None
        cfg.CONF.set_override("notification_driver", [test_notifier.__name__])

        self.tenant_id_fcn_p = mock.patch('quantum.plugins.cisco.l3.db.'
                                          'l3_router_appliance_db.'
                                          'L3_router_appliance_db_mixin.'
                                          'l3_tenant_id')
        self.tenant_id_fcn = self.tenant_id_fcn_p.start()
        self.tenant_id_fcn = mock.MagicMock(return_value='L3AdminTenantId')

    def tearDown(self):
        self.tenant_id_fcn_p.stop()
        super(myTestCase, self).tearDown()

    def basic_test(self):
        plugin = QuantumManager.get_plugin()
        res = plugin.l3_tenant_id()
        self.assertEqual(plugin.l3_tenant_id(), 'L3AdminTenantId')
