# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

import random

import mox

from quantum import context
from quantum.openstack.common import uuidutils
from quantum.plugins.nec.common import ofc_client
from quantum.plugins.nec.db import api as ndb
from quantum.plugins.nec.db import models as nmodels
from quantum.plugins.nec import drivers
from quantum.tests import base


class TestConfig(object):
    """Configuration for this test."""
    host = '127.0.0.1'
    port = 8888


class TremaDriverTestBase(base.BaseTestCase):

    driver_name = "trema"

    def setUp(self):
        super(TremaDriverTestBase, self).setUp()
        self.mox = mox.Mox()
        self.driver = drivers.get_driver(self.driver_name)(TestConfig)
        self.mox.StubOutWithMock(ofc_client.OFCClient, 'do_request')
        self.addCleanup(self.mox.UnsetStubs)

    def get_ofc_item_random_params(self):
        """create random parameters for ofc_item test."""
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        mac = ':'.join(['%x' % random.randint(0, 255) for i in xrange(6)])
        portinfo = nmodels.PortInfo(id=port_id, datapath_id="0x123456789",
                                    port_no=1234, vlan_id=321,
                                    mac=mac)
        return tenant_id, network_id, portinfo


class TremaDriverNetworkTestBase(TremaDriverTestBase):

    def test_create_tenant(self):
        t, n, p = self.get_ofc_item_random_params()
        # There is no API call.
        self.mox.ReplayAll()
        ret = self.driver.create_tenant('dummy_desc', t)
        self.mox.VerifyAll()
        ofc_t_path = "/tenants/%s" % t
        self.assertEqual(ofc_t_path, ret)

    def test_update_tenant(self):
        t, n, p = self.get_ofc_item_random_params()
        path = "/tenants/%s" % t
        # There is no API call.
        self.mox.ReplayAll()
        self.driver.update_tenant(path, 'dummy_desc')
        self.mox.VerifyAll()

    def testc_delete_tenant(self):
        t, n, p = self.get_ofc_item_random_params()
        path = "/tenants/%s" % t
        # There is no API call.
        self.mox.ReplayAll()
        self.driver.delete_tenant(path)
        self.mox.VerifyAll()

    def testa_create_network(self):
        t, n, p = self.get_ofc_item_random_params()
        description = "desc of %s" % n

        body = {'id': n, 'description': description}
        ofc_client.OFCClient.do_request("POST", "/networks", body=body)
        self.mox.ReplayAll()

        ret = self.driver.create_network(t, description, n)
        self.mox.VerifyAll()
        self.assertEqual(ret, '/networks/%s' % n)

    def testc_delete_network(self):
        t, n, p = self.get_ofc_item_random_params()

        net_path = "/networks/%s" % n
        ofc_client.OFCClient.do_request("DELETE", net_path)
        self.mox.ReplayAll()

        self.driver.delete_network(net_path)
        self.mox.VerifyAll()


class TremaPortBaseDriverTest(TremaDriverNetworkTestBase):

    driver_name = "trema_port"

    def test_filter_supported(self):
        self.assertTrue(self.driver.filter_supported())

    def testd_create_port(self):
        _t, n, p = self.get_ofc_item_random_params()

        net_path = "/networks/%s" % n
        body = {'id': p.id,
                'datapath_id': p.datapath_id,
                'port': str(p.port_no),
                'vid': str(p.vlan_id)}
        ofc_client.OFCClient.do_request("POST",
                                        "/networks/%s/ports" % n, body=body)
        self.mox.ReplayAll()

        ret = self.driver.create_port(net_path, p, p.id)
        self.mox.VerifyAll()
        self.assertEqual(ret, '/networks/%s/ports/%s' % (n, p.id))

    def testd_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()

        p_path = "/networks/%s/ports/%s" % (n, p.id)
        ofc_client.OFCClient.do_request("DELETE", p_path)
        self.mox.ReplayAll()

        self.driver.delete_port(p_path)
        self.mox.VerifyAll()


class TremaPortMACBaseDriverTest(TremaDriverNetworkTestBase):

    driver_name = "trema_portmac"

    def test_filter_supported(self):
        self.assertTrue(self.driver.filter_supported())

    def testd_create_port(self):
        t, n, p = self.get_ofc_item_random_params()
        dummy_port = "dummy-%s" % p.id

        net_path = "/networks/%s" % n
        path_1 = "/networks/%s/ports" % n
        body_1 = {'id': dummy_port,
                  'datapath_id': p.datapath_id,
                  'port': str(p.port_no),
                  'vid': str(p.vlan_id)}
        ofc_client.OFCClient.do_request("POST", path_1, body=body_1)
        path_2 = "/networks/%s/ports/%s/attachments" % (n, dummy_port)
        body_2 = {'id': p.id, 'mac': p.mac}
        ofc_client.OFCClient.do_request("POST", path_2, body=body_2)
        path_3 = "/networks/%s/ports/%s" % (n, dummy_port)
        ofc_client.OFCClient.do_request("DELETE", path_3)
        self.mox.ReplayAll()

        ret = self.driver.create_port(net_path, p, p.id)
        self.mox.VerifyAll()
        port_path = "/networks/%s/ports/%s/attachments/%s" % (n, dummy_port,
                                                              p.id)
        self.assertEqual(ret, port_path)

    def testd_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()
        dummy_port = "dummy-%s" % p.id

        path = "/networks/%s/ports/%s/attachments/%s" % (n, dummy_port, p.id)
        ofc_client.OFCClient.do_request("DELETE", path)
        self.mox.ReplayAll()

        self.driver.delete_port(path)
        self.mox.VerifyAll()


class TremaMACBaseDriverTest(TremaDriverNetworkTestBase):

    driver_name = "trema_mac"

    def test_filter_supported(self):
        self.assertFalse(self.driver.filter_supported())

    def testd_create_port(self):
        t, n, p = self.get_ofc_item_random_params()

        net_path = "/networks/%s" % n
        path = "/networks/%s/attachments" % n
        body = {'id': p.id, 'mac': p.mac}
        ofc_client.OFCClient.do_request("POST", path, body=body)
        self.mox.ReplayAll()

        ret = self.driver.create_port(net_path, p, p.id)
        self.mox.VerifyAll()
        self.assertEqual(ret, '/networks/%s/attachments/%s' % (n, p.id))

    def testd_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()

        path = "/networks/%s/attachments/%s" % (n, p.id)
        ofc_client.OFCClient.do_request("DELETE", path)
        self.mox.ReplayAll()

        self.driver.delete_port(path)
        self.mox.VerifyAll()


class TremaFilterDriverTest(TremaDriverTestBase):
    def _test_create_filter(self, filter_dict=None, filter_post=None,
                            filter_wildcards=None, no_portinfo=False):
        t, n, p = self.get_ofc_item_random_params()
        src_mac = ':'.join(['%x' % random.randint(0, 255) for i in xrange(6)])
        if filter_wildcards is None:
            filter_wildcards = []

        f = {'tenant_id': t,
             'id': uuidutils.generate_uuid(),
             'network_id': n,
             'priority': 123,
             'action': "ACCEPT",
             'in_port': p.id,
             'src_mac': src_mac,
             'dst_mac': "",
             'eth_type': 0,
             'src_cidr': "",
             'dst_cidr': "",
             'src_port': 0,
             'dst_port': 0,
             'protocol': "TCP",
             'admin_state_up': True,
             'status': "ACTIVE"}
        if filter_dict:
            f.update(filter_dict)
        print 'filter=%s' % f

        net_path = "/networks/%s" % n

        all_wildcards_ofp = ['dl_vlan', 'dl_vlan_pcp', 'nw_tos',
                             'in_port', 'dl_src', 'dl_dst',
                             'nw_src', 'nw_dst',
                             'dl_type', 'nw_proto',
                             'tp_src', 'tp_dst']
        all_wildcards_non_ofp = ['in_datapath_id', 'slice']

        body = {'id': f['id'],
                'action': 'ALLOW',
                'priority': 123,
                'slice': n,
                'in_datapath_id': '0x123456789',
                'in_port': 1234,
                'nw_proto': '0x6',
                'dl_type': '0x800',
                'dl_src': src_mac}
        if filter_post:
            body.update(filter_post)

        if no_portinfo:
            filter_wildcards += ['in_datapath_id', 'in_port']
            p = None

        for field in filter_wildcards:
            if field in body:
                del body[field]

        ofp_wildcards = ["%s:32" % _f if _f in ['nw_src', 'nw_dst'] else _f
                         for _f in all_wildcards_ofp if _f not in body]
        body['ofp_wildcards'] = ','.join(ofp_wildcards)

        non_ofp_wildcards = [_f for _f in all_wildcards_non_ofp
                             if _f not in body]
        if non_ofp_wildcards:
            body['wildcards'] = ','.join(non_ofp_wildcards)

        ofc_client.OFCClient.do_request("POST", "/filters", body=body)
        self.mox.ReplayAll()

        ret = self.driver.create_filter(net_path, f, p, f['id'])
        self.mox.VerifyAll()
        self.assertEqual(ret, '/filters/%s' % f['id'])

    def test_create_filter_accept(self):
        self._test_create_filter(filter_dict={'action': 'ACCEPT'})

    def test_create_filter_allow(self):
        self._test_create_filter(filter_dict={'action': 'ALLOW'})

    def test_create_filter_deny(self):
        self._test_create_filter(filter_dict={'action': 'DENY'},
                                 filter_post={'action': 'DENY'})

    def test_create_filter_drop(self):
        self._test_create_filter(filter_dict={'action': 'DROP'},
                                 filter_post={'action': 'DENY'})

    def test_create_filter_no_port(self):
        self._test_create_filter(no_portinfo=True)

    def test_create_filter_src_mac_wildcard(self):
        self._test_create_filter(filter_dict={'src_mac': ''},
                                 filter_wildcards=['dl_src'])

    def test_create_filter_dst_mac(self):
        dst_mac = ':'.join(['%x' % random.randint(0, 255) for i in xrange(6)])
        self._test_create_filter(filter_dict={'dst_mac': dst_mac},
                                 filter_post={'dl_dst': dst_mac})

    def test_create_filter_src_cidr(self):
        src_cidr = '10.2.0.0/24'
        self._test_create_filter(filter_dict={'src_cidr': src_cidr},
                                 filter_post={'nw_src': src_cidr})

    def test_create_filter_dst_cidr(self):
        dst_cidr = '192.168.10.0/24'
        self._test_create_filter(filter_dict={'dst_cidr': dst_cidr},
                                 filter_post={'nw_dst': dst_cidr})

    def test_create_filter_proto_icmp(self):
        self._test_create_filter(
            filter_dict={'protocol': 'icmp'},
            filter_post={'dl_type': '0x800', 'nw_proto': '0x1'})

    def test_create_filter_proto_tcp(self):
        self._test_create_filter(
            filter_dict={'protocol': 'tcp'},
            filter_post={'dl_type': '0x800', 'nw_proto': '0x6'})

    def test_create_filter_proto_udp(self):
        self._test_create_filter(
            filter_dict={'protocol': 'udp'},
            filter_post={'dl_type': '0x800', 'nw_proto': '0x11'})

    def test_create_filter_proto_arp(self):
        self._test_create_filter(
            filter_dict={'protocol': 'arp'},
            filter_post={'dl_type': '0x806'},
            filter_wildcards=['nw_proto'])

    def test_create_filter_proto_misc(self):
        self._test_create_filter(
            filter_dict={'protocol': '0x33', 'eth_type': '0x900'},
            filter_post={'dl_type': '0x900', 'nw_proto': '0x33'})

    def test_create_filter_proto_misc_dl_type_wildcard(self):
        self._test_create_filter(
            filter_dict={'protocol': '0x33', 'ether_type': ''},
            filter_post={'nw_proto': '0x33'},
            filter_wildcards=['dl_type'])

    def test_create_filter_proto_wildcard(self):
        self._test_create_filter(
            filter_dict={'protocol': ''},
            filter_wildcards=['dl_type', 'nw_proto'])

    def test_create_filter_src_dst_port(self):
        self._test_create_filter(filter_dict={'src_port': 8192,
                                              'dst_port': 4096},
                                 filter_post={'tp_src': '0x2000',
                                              'tp_dst': '0x1000'})

    def testb_delete_filter(self):
        t, n, p = self.get_ofc_item_random_params()

        f_path = "/filters/%s" % uuidutils.generate_uuid()
        ofc_client.OFCClient.do_request("DELETE", f_path)
        self.mox.ReplayAll()

        self.driver.delete_filter(f_path)
        self.mox.VerifyAll()


def generate_random_ids(count=1):
    if count == 1:
        return uuidutils.generate_uuid()
    else:
        return [uuidutils.generate_uuid() for i in xrange(count)]


class TremaIdConvertTest(base.BaseTestCase):
    driver_name = 'trema'

    def setUp(self):
        super(TremaIdConvertTest, self).setUp()
        self.driver = drivers.get_driver(self.driver_name)(TestConfig)
        self.mox = mox.Mox()
        self.ctx = self.mox.CreateMock(context.Context)
        self.addCleanup(self.mox.UnsetStubs)

    def test_convert_tenant_id(self):
        ofc_t_id = generate_random_ids(1)
        ret = self.driver.convert_ofc_tenant_id(self.ctx, ofc_t_id)
        self.assertEqual(ret, '/tenants/%s' % ofc_t_id)

    def test_convert_tenant_id_noconv(self):
        ofc_t_id = '/tenants/%s' % generate_random_ids(1)
        ret = self.driver.convert_ofc_tenant_id(self.ctx, ofc_t_id)
        self.assertEqual(ret, ofc_t_id)

    def test_convert_network_id(self):
        t_id, ofc_t_id, ofc_n_id = generate_random_ids(3)

        ret = self.driver.convert_ofc_network_id(self.ctx, ofc_n_id, t_id)
        self.assertEqual(ret, ('/networks/%s' % ofc_n_id))

    def test_convert_network_id_noconv(self):
        t_id = 'dummy'
        ofc_t_id, ofc_n_id = generate_random_ids(2)
        ofc_n_id = '/networks/%s' % ofc_n_id
        self.driver.convert_ofc_network_id(self.ctx, ofc_n_id, t_id)

    def test_convert_filter_id(self):
        ofc_f_id = generate_random_ids(1)
        ret = self.driver.convert_ofc_filter_id(self.ctx, ofc_f_id)
        self.assertEqual(ret, '/filters/%s' % ofc_f_id)

    def test_convert_filter_id_noconv(self):
        ofc_f_id = '/filters/%s' % generate_random_ids(1)
        ret = self.driver.convert_ofc_filter_id(self.ctx, ofc_f_id)
        self.assertEqual(ret, ofc_f_id)


class TremaIdConvertTestBase(base.BaseTestCase):
    def setUp(self):
        super(TremaIdConvertTestBase, self).setUp()
        self.mox = mox.Mox()
        self.driver = drivers.get_driver(self.driver_name)(TestConfig)
        self.ctx = self.mox.CreateMock(context.Context)
        self.ctx.session = "session"
        self.mox.StubOutWithMock(ndb, 'get_ofc_id_lookup_both')
        self.addCleanup(self.mox.UnsetStubs)

    def _test_convert_port_id(self, port_path_template):
        t_id, n_id = generate_random_ids(2)
        ofc_n_id, ofc_p_id = generate_random_ids(2)

        ndb.get_ofc_id_lookup_both(
            self.ctx.session, 'ofc_network', n_id).AndReturn(ofc_n_id)
        self.mox.ReplayAll()

        ret = self.driver.convert_ofc_port_id(self.ctx, ofc_p_id, t_id, n_id)
        exp = port_path_template % {'network': ofc_n_id, 'port': ofc_p_id}
        self.assertEqual(ret, exp)
        self.mox.VerifyAll()

    def _test_convert_port_id_with_new_network_id(self, port_path_template):
        t_id, n_id = generate_random_ids(2)
        ofc_n_id, ofc_p_id = generate_random_ids(2)

        ofc_n_path = '/networks/%s' % ofc_n_id
        ndb.get_ofc_id_lookup_both(
            self.ctx.session, 'ofc_network', n_id).AndReturn(ofc_n_path)
        self.mox.ReplayAll()

        ret = self.driver.convert_ofc_port_id(self.ctx, ofc_p_id, t_id, n_id)
        exp = port_path_template % {'network': ofc_n_id, 'port': ofc_p_id}
        print 'exp=', exp
        print 'ret=', ret
        self.assertEqual(ret, exp)
        self.mox.VerifyAll()

    def _test_convert_port_id_noconv(self, port_path_template):
        t_id = n_id = 'dummy'
        ofc_n_id, ofc_p_id = generate_random_ids(2)
        ofc_p_id = port_path_template % {'network': ofc_n_id, 'port': ofc_p_id}
        ret = self.driver.convert_ofc_port_id(self.ctx, ofc_p_id, t_id, n_id)
        self.assertEqual(ret, ofc_p_id)


class TremaIdConvertPortBaseTest(TremaIdConvertTestBase):
    driver_name = "trema_port"

    def test_convert_port_id(self):
        self._test_convert_port_id('/networks/%(network)s/ports/%(port)s')

    def test_convert_port_id_with_new_network_id(self):
        self._test_convert_port_id_with_new_network_id(
            '/networks/%(network)s/ports/%(port)s')

    def test_convert_port_id_noconv(self):
        self._test_convert_port_id_noconv(
            '/networs/%(network)s/ports/%(port)s')


class TremaIdConvertPortMACBaseTest(TremaIdConvertTestBase):
    driver_name = "trema_portmac"

    def test_convert_port_id(self):
        self._test_convert_port_id(
            '/networks/%(network)s/ports/dummy-%(port)s/attachments/%(port)s')

    def test_convert_port_id_with_new_network_id(self):
        self._test_convert_port_id_with_new_network_id(
            '/networks/%(network)s/ports/dummy-%(port)s/attachments/%(port)s')

    def test_convert_port_id_noconv(self):
        self._test_convert_port_id_noconv(
            '/networs/%(network)s/ports/dummy-%(port)s/attachments/%(port)s')


class TremaIdConvertMACBaseTest(TremaIdConvertTestBase):
    driver_name = "trema_mac"

    def test_convert_port_id(self):
        self._test_convert_port_id(
            '/networks/%(network)s/attachments/%(port)s')

    def test_convert_port_id_with_new_network_id(self):
        self._test_convert_port_id_with_new_network_id(
            '/networks/%(network)s/attachments/%(port)s')

    def test_convert_port_id_noconv(self):
        self._test_convert_port_id_noconv(
            '/networs/%(network)s/attachments/%(port)s')
