# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (C) 2012 Midokura Japan K.K.
# Copyright (C) 2013 Midokura PTE LTD
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
#
# @author: Rossella Sblendido, Midokura Europe SARL
# @author: Ryu Ishimoto, Midokura Japan KK
# @author: Tomoe Sugihara, Midokura Japan KK

import mock
import os
import sys

import quantum.common.test_lib as test_lib
import quantum.tests.unit.midonet.mock_lib as mock_lib
import quantum.tests.unit.test_db_plugin as test_plugin


MIDOKURA_PKG_PATH = "quantum.plugins.midonet.plugin"


# Need to mock the midonetclient module since the plugin will try to load it.
sys.modules["midonetclient"] = mock.Mock()


class MidonetPluginV2TestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = ('%s.MidonetPluginV2' % MIDOKURA_PKG_PATH)

    def setUp(self):
        self.mock_api = mock.patch(
            'quantum.plugins.midonet.midonet_lib.MidoClient')
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(
            etc_path, 'midonet.ini.test')]

        self.instance = self.mock_api.start()
        mock_cfg = mock_lib.MidonetLibMockConfig(self.instance.return_value)
        mock_cfg.setup()
        super(MidonetPluginV2TestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        super(MidonetPluginV2TestCase, self).tearDown()
        self.mock_api.stop()


class TestMidonetNetworksV2(test_plugin.TestNetworksV2,
                            MidonetPluginV2TestCase):
    pass


class TestMidonetSubnetsV2(test_plugin.TestSubnetsV2,
                           MidonetPluginV2TestCase):

    # IPv6 is not supported by MidoNet yet.  Ignore tests that attempt to
    # create IPv6 subnet.
    def test_create_subnet_inconsistent_ipv6_cidrv4(self):
        pass

    def test_create_subnet_inconsistent_ipv6_dns_v4(self):
        pass

    def test_create_subnet_with_v6_allocation_pool(self):
        pass

    def test_update_subnet_inconsistent_ipv6_gatewayv4(self):
        pass

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        pass

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        pass

    def test_create_subnet_inconsistent_ipv6_gatewayv4(self):
        pass

    # Multiple subnets in a network is not supported by MidoNet yet.  Ignore
    # tests that attempt to create them.

    def test_create_subnets_bulk_emulated(self):
        pass

    def test_create_two_subnets(self):
        pass

    def test_list_subnets(self):
        pass

    def test_list_subnets_with_parameter(self):
        pass

    def test_create_two_subnets_same_cidr_returns_400(self):
        pass


class TestMidonetPortsV2(test_plugin.TestPortsV2,
                         MidonetPluginV2TestCase):

    # IPv6 is not supported by MidoNet yet.  Ignore tests that attempt to
    # create IPv6 subnet.

    def test_requested_subnet_id_v4_and_v6(self):
        pass

    # Multiple subnets in a network is not supported by MidoNet yet.  Ignore
    # tests that attempt to create them.

    def test_overlapping_subnets(self):
            pass
