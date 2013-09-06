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


from neutron.api.v2 import attributes as attr
from neutron.common.test_lib import test_config
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import db_base_plugin_v2
from neutron.db import portsecurity_db
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import portsecurity as psec
from neutron.manager import NeutronManager
from neutron.tests.unit import test_db_plugin

DB_PLUGIN_KLASS = ('neutron.tests.unit.test_extension_allowedaddresspairs.'
                   'AllowedAddressPairTestPlugin')


class AllowedAddressPairTestCase(test_db_plugin.NeutronDbPluginV2TestCase):
    def setUp(self, plugin=None):
        super(AllowedAddressPairTestCase, self).setUp()

        # Check if a plugin supports security groups
        plugin_obj = NeutronManager.get_plugin()
        self._skip_port_security = ('port-security' not in
                                    plugin_obj.supported_extension_aliases)


class AllowedAddressPairTestPlugin(portsecurity_db.PortSecurityDbMixin,
                                   db_base_plugin_v2.NeutronDbPluginV2,
                                   addr_pair_db.AllowedAddressPairsMixin):

    """Test plugin that implements necessary calls on create/delete port for
    associating ports with port security and allowed address pairs.
    """

    supported_extension_aliases = ["allowed-address-pairs"]

    def create_port(self, context, port):
        p = port['port']
        with context.session.begin(subtransactions=True):
            neutron_db = super(AllowedAddressPairTestPlugin, self).create_port(
                context, port)
            p.update(neutron_db)
            if attr.is_attr_set(p.get(addr_pair.ADDRESS_PAIRS)):
                self._process_create_allowed_address_pairs(
                    context, p,
                    p[addr_pair.ADDRESS_PAIRS])
            else:
                p[addr_pair.ADDRESS_PAIRS] = None

        return port['port']

    def update_port(self, context, id, port):
        delete_addr_pairs = self._check_update_deletes_allowed_address_pairs(
            port)
        has_addr_pairs = self._check_update_has_allowed_address_pairs(port)

        with context.session.begin(subtransactions=True):
            ret_port = super(AllowedAddressPairTestPlugin, self).update_port(
                context, id, port)
            # copy values over - but not fixed_ips
            port['port'].pop('fixed_ips', None)
            ret_port.update(port['port'])

            if (delete_addr_pairs or has_addr_pairs):
                # delete address pairds and readd them
                self._delete_allowed_address_pairs(context, id)
                self._process_create_allowed_address_pairs(
                    context, ret_port,
                    ret_port[addr_pair.ADDRESS_PAIRS])

        return ret_port


class AllowedAddressPairDBTestCase(AllowedAddressPairTestCase):
    def setUp(self, plugin=None):
        test_config['plugin_name_v2'] = DB_PLUGIN_KLASS
        super(AllowedAddressPairDBTestCase, self).setUp()

    def tearDown(self):
        del test_config['plugin_name_v2']
        super(AllowedAddressPairDBTestCase, self).tearDown()


class AllowedAddressPairDBTestCaseXML(AllowedAddressPairDBTestCase):
    fmt = 'xml'


class TestAllowedAddressPairs(AllowedAddressPairDBTestCase):

    def test_create_port_allowed_address_pairs(self):
        with self.network() as net:
            address_pairs = [{'mac_address': '00:00:00:00:00:01',
                              'ip_address': '10.0.0.1'}]
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=(addr_pair.ADDRESS_PAIRS,),
                                    allowed_address_pairs=address_pairs)
            port = self.deserialize(self.fmt, res)
            self.assertEqual(port['port'][addr_pair.ADDRESS_PAIRS],
                             address_pairs)
            self._delete('ports', port['port']['id'])

    def test_create_port_security_true_allowed_address_pairs(self):
        if self._skip_port_security:
            self.skipTest("Plugin does not implement port-security extension")

        with self.network() as net:
            address_pairs = [{'mac_address': '00:00:00:00:00:01',
                              'ip_address': '10.0.0.1'}]
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=('port_security_enabled',
                                              addr_pair.ADDRESS_PAIRS,),
                                    port_security_enabled=True,
                                    allowed_address_pairs=address_pairs)
            port = self.deserialize(self.fmt, res)
            self.assertEqual(port['port'][psec.PORTSECURITY], True)
            self.assertEqual(port['port'][addr_pair.ADDRESS_PAIRS],
                             address_pairs)
            self._delete('ports', port['port']['id'])

    def test_create_port_security_false_allowed_address_pairs(self):
        if self._skip_port_security:
            self.skipTest("Plugin does not implement port-security extension")

        with self.network() as net:
            address_pairs = [{'mac_address': '00:00:00:00:00:01',
                              'ip_address': '10.0.0.1'}]
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=('port_security_enabled',
                                              addr_pair.ADDRESS_PAIRS,),
                                    port_security_enabled=False,
                                    allowed_address_pairs=address_pairs)
            self.deserialize(self.fmt, res)
            self.assertEqual(res.status_int, 409)

    def test_create_port_bad_mac(self):
        address_pairs = [{'mac_address': 'invalid_mac',
                          'ip_address': '10.0.0.1'}]
        self._create_port_with_address_pairs(address_pairs, 400)

    def test_create_port_bad_ip(self):
        address_pairs = [{'mac_address': '00:00:00:00:00:01',
                          'ip_address': '10.0.0.1222'}]
        self._create_port_with_address_pairs(address_pairs, 400)

    def test_create_missing_ip_field(self):
        address_pairs = [{'mac_address': '00:00:00:00:00:01'}]
        self._create_port_with_address_pairs(address_pairs, 400)

    def test_create_duplicate_mac_ip(self):
        address_pairs = [{'mac_address': '00:00:00:00:00:01',
                          'ip_address': '10.0.0.1'},
                         {'mac_address': '00:00:00:00:00:01',
                          'ip_address': '10.0.0.1'}]
        self._create_port_with_address_pairs(address_pairs, 400)

    def test_create_port_extra_args(self):
        address_pairs = [{'mac_address': '00:00:00:00:00:01',
                          'ip_address': '10.0.0.1',
                          'icbb': 'agreed'}]
        self._create_port_with_address_pairs(address_pairs, 400)

    def _create_port_with_address_pairs(self, address_pairs, ret_code):
        with self.network() as net:
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=(addr_pair.ADDRESS_PAIRS,),
                                    allowed_address_pairs=address_pairs)
            self.deserialize(self.fmt, res)
            self.assertEqual(res.status_int, ret_code)

    def test_update_add_address_pairs(self):
        with self.network() as net:
            res = self._create_port(self.fmt, net['network']['id'])
            port = self.deserialize(self.fmt, res)
            address_pairs = [{'mac_address': '00:00:00:00:00:01',
                              'ip_address': '10.0.0.1'}]
            update_port = {'port': {addr_pair.ADDRESS_PAIRS:
                                    address_pairs}}
            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            port = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(port['port'][addr_pair.ADDRESS_PAIRS],
                             address_pairs)
            self._delete('ports', port['port']['id'])

    def test_create_address_gets_port_mac(self):
        with self.network() as net:
            address_pairs = [{'ip_address': '23.23.23.23'}]
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=('port_security_enabled',
                                              addr_pair.ADDRESS_PAIRS,),
                                    allowed_address_pairs=address_pairs)
            port = self.deserialize(self.fmt, res)['port']
            port_addr_mac = port[addr_pair.ADDRESS_PAIRS][0]['mac_address']
            self.assertEqual(port_addr_mac,
                             port['mac_address'])
            self._delete('ports', port['id'])

    def test_update_address_pair_to_match_fixed_ip_and_mac(self):
        with self.network() as net:
            with self.subnet(network=net):
                res = self._create_port(self.fmt, net['network']['id'])
                port = self.deserialize(self.fmt, res)['port']
                address_pairs = [{'mac_address': port['mac_address'],
                                  'ip_address':
                                  port['fixed_ips'][0]['ip_address']}]

                update_port = {'port': {addr_pair.ADDRESS_PAIRS:
                                        address_pairs}}
                req = self.new_update_request('ports', update_port,
                                              port['id'])
                res = req.get_response(self.api)
                self.assertEqual(res.status_int, 400)
                self._delete('ports', port['id'])

    def test_update_port_security_off_address_pairs(self):
        if self._skip_port_security:
            self.skipTest("Plugin does not implement port-security extension")
        with self.network() as net:
            with self.subnet(network=net):
                address_pairs = [{'mac_address': '00:00:00:00:00:01',
                                  'ip_address': '10.0.0.1'}]
                res = self._create_port(self.fmt, net['network']['id'],
                                        arg_list=('port_security_enabled',
                                                  addr_pair.ADDRESS_PAIRS,),
                                        port_security_enabled=True,
                                        allowed_address_pairs=address_pairs)
                port = self.deserialize(self.fmt, res)
                print port
                update_port = {'port': {psec.PORTSECURITY: False}}
                # If plugin implements security groups we also need to remove
                # the security group on port.
                plugin_obj = NeutronManager.get_plugin()
                if 'security-groups' in plugin_obj.supported_extension_aliases:
                    update_port['port']['security_groups'] = []
                req = self.new_update_request('ports', update_port,
                                              port['port']['id'])
                res = req.get_response(self.api)
                self.assertEqual(res.status_int, 409)
                self._delete('ports', port['port']['id'])

    def test_create_port_remove_allowed_address_pairs(self):
        with self.network() as net:
            address_pairs = [{'mac_address': '00:00:00:00:00:01',
                              'ip_address': '10.0.0.1'}]
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=(addr_pair.ADDRESS_PAIRS,),
                                    allowed_address_pairs=address_pairs)
            port = self.deserialize(self.fmt, res)
            update_port = {'port': {addr_pair.ADDRESS_PAIRS: []}}
            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            port = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(port['port'][addr_pair.ADDRESS_PAIRS], [])
            self._delete('ports', port['port']['id'])
