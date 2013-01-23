# Copyright (c) 2012 OpenStack, LLC.
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

import unittest

from quantum.tests.unit import test_db_plugin as test_plugin


class N1kvPluginTestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = ('quantum.plugins.cisco.n1kv.'
                    'n1k_quantum_plugin.N1KQuantumPluginV2')

    def setUp(self):
        super(N1kvPluginTestCase, self).setUp(self._plugin_name)


class TestN1kvRefactor(unittest.TestCase):
    def setUp(self):
        pass

    def test_foo(self):
        self.assertTrue(1 == 1)


class TestN1kvBasicGet(test_plugin.TestBasicGet,
                       N1kvPluginTestCase):
    def setUp(self):
        super(N1kvPluginTestCase, self).setUp(self._plugin_name)


class TestN1kvHTTPResponse(test_plugin.TestV2HTTPResponse,
                           N1kvPluginTestCase):
    pass


class TestN1kvPorts(test_plugin.TestPortsV2,
                    N1kvPluginTestCase):
    pass


class TestN1kvNetworks(test_plugin.TestNetworksV2,
                       N1kvPluginTestCase):
    pass
