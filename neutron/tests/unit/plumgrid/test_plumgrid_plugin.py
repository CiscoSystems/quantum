# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 PLUMgrid, Inc. All Rights Reserved.
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
# @author: Edgar Magana, emagana@plumgrid.com, PLUMgrid, Inc.

"""
Test cases for  Neutron PLUMgrid Plug-in
"""

import mock

from neutron.extensions import portbindings
from neutron.manager import NeutronManager
from neutron.openstack.common import importutils
from neutron.plugins.plumgrid.plumgrid_plugin import plumgrid_plugin
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit import test_db_plugin as test_plugin


PLUM_DRIVER = ('neutron.plugins.plumgrid.drivers.fake_plumlib.Plumlib')
FAKE_DIRECTOR = '1.1.1.1'
FAKE_PORT = '1234'
FAKE_USERNAME = 'fake_admin'
FAKE_PASSWORD = 'fake_password'
FAKE_TIMEOUT = '0'


class PLUMgridPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):
    _plugin_name = ('neutron.plugins.plumgrid.plumgrid_plugin.'
                    'plumgrid_plugin.NeutronPluginPLUMgridV2')

    def setUp(self):
        def mocked_plumlib_init(self):
            director_plumgrid = FAKE_DIRECTOR
            director_port = FAKE_PORT
            director_username = FAKE_USERNAME
            director_password = FAKE_PASSWORD
            timeout = FAKE_TIMEOUT
            self._plumlib = importutils.import_object(PLUM_DRIVER)
            self._plumlib.director_conn(director_plumgrid,
                                        director_port, timeout,
                                        director_username,
                                        director_password)

        with mock.patch.object(plumgrid_plugin.NeutronPluginPLUMgridV2,
                               'plumgrid_init', new=mocked_plumlib_init):
            super(PLUMgridPluginV2TestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        super(PLUMgridPluginV2TestCase, self).tearDown()


class TestPlumgridPluginNetworksV2(test_plugin.TestNetworksV2,
                                   PLUMgridPluginV2TestCase):
    pass


class TestPlumgridV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                                 PLUMgridPluginV2TestCase):
    pass


class TestPlumgridPluginPortsV2(test_plugin.TestPortsV2,
                                PLUMgridPluginV2TestCase):
    def test_range_allocation(self):
        self.skipTest("Plugin does not support Neutron allocation process")


class TestPlumgridPluginSubnetsV2(test_plugin.TestSubnetsV2,
                                  PLUMgridPluginV2TestCase):
    def test_create_subnet_default_gw_conflict_allocation_pool_returns_409(
            self):
        self.skipTest("Plugin does not support Neutron allocation process")

    def test_create_subnet_defaults(self):
        self.skipTest("Plugin does not support Neutron allocation process")

    def test_create_subnet_gw_values(self):
        self.skipTest("Plugin does not support Neutron allocation process")

    def test_update_subnet_gateway_in_allocation_pool_returns_409(self):
        self.skipTest("Plugin does not support Neutron allocation process")


class TestPlumgridPluginPortBinding(PLUMgridPluginV2TestCase,
                                    test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_IOVISOR

    def setUp(self):
        super(TestPlumgridPluginPortBinding, self).setUp()


class TestPlumgridNetworkAdminState(PLUMgridPluginV2TestCase):
    def test_network_admin_state(self):
        name = 'network_test'
        admin_status_up = False
        tenant_id = 'tenant_test'
        network = {'network': {'name': name,
                               'admin_state_up': admin_status_up,
                               'tenant_id': tenant_id}}
        plugin = NeutronManager.get_plugin()
        self.assertEqual(plugin._network_admin_state(network), network)


class TestPlumgridAllocationPool(PLUMgridPluginV2TestCase):
    def test_allocate_pools_for_subnet(self):
        cidr = '10.0.0.0/24'
        gateway_ip = '10.0.0.254'
        subnet = {'gateway_ip': gateway_ip,
                  'cidr': cidr,
                  'ip_version': 4}
        allocation_pool = [{"start": '10.0.0.2',
                            "end": '10.0.0.253'}]
        context = None
        plugin = NeutronManager.get_plugin()
        pool = plugin._allocate_pools_for_subnet(context, subnet)
        self.assertEqual(allocation_pool, pool)
