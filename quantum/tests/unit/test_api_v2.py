import json
import logging
import unittest
from webob import exc
import netaddr

from quantum.api.v2.router import APIRouter
from quantum.manager import QuantumManager
from quantum.tests.unit.testlib_api import create_request
from quantum.wsgi import Serializer, XMLDeserializer, JSONDeserializer


LOG = logging.getLogger('quantum.tests.api_v2_test')


class APIv2TestCase(unittest.TestCase):
    def setUp(self):
        super(APIv2TestCase, self).setUp()
        self._tenant_id = "test-tenant"

        json_deserializer = JSONDeserializer()
        self._deserializers = {
            'application/json': json_deserializer,
        }

        plugin = "quantum.plugins.sample.SamplePluginV2.FakePlugin"
        self.api = APIRouter({"plugin_provider": plugin})

    def _req(self, method, resource, data=None, fmt='json', id=None):
        if id:
            path = "/%(resource)s/%(id)s.%(fmt)s" % locals()
        else:
            path = "/%(resource)s.%(fmt)s" % locals()
        content_type = "application/%s" % fmt
        body = None
        if data:
            body = Serializer().serialize(data, content_type)
        return create_request(path, body, content_type, method)

    # Yeah, they're factories. And you better be ok with it.
    # NOTE(BOOM) OMG, the explosion!!!
    def new_create_request(self, resource, data, fmt='json'):
        return self._req('POST', resource, data, fmt)

    def new_list_request(self, resource, fmt='json'):
        return self._req('GET', resource, None, fmt)

    def new_show_request(self, resource, id, fmt='json'):
        return self._req('GET', resource, None, fmt, id=id)

    def new_delete_request(self, resource, id, fmt='json'):
        return self._req('DELETE', resource, None, fmt, id=id)

    def new_update_request(self, resource, data, id, fmt='json'):
        return self._req('PUT', resource, data, fmt, id=id)

    def deserialize(self, content_type, response):
        ctype = "application/%s" % content_type
        data = self._deserializers[ctype].\
                            deserialize(response.body)['body']
        return data

    def _create_network(self, fmt, name, admin_status_up,
                        custom_req_body=None,
                        expected_res_status=None):
        LOG.debug("Creating network")
        data = {'network': {'name': name,
                            'admin_state_up': admin_status_up}}
        network_req = self.new_create_request('networks', data, fmt)
        network_res = network_req.get_response(self.api)
        return network_res


class TestV2HTTPResponse(APIv2TestCase):
    def setUp(self):
        super(TestV2HTTPResponse, self).setUp()
        res = self._create_network("json", "net1", True)
        self.net = self.deserialize("json", res)

    def tearDown(self):
        super(TestV2HTTPResponse, self).tearDown()

    def test_create_returns_201(self):
        res = self._create_network('json', "net2", True)
        self.assertEquals(res.status_int, 201)

    def test_list_returns_200(self):
        req = self.new_list_request('networks')
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 200)

    def test_show_returns_200(self):
        req = self.new_show_request('networks', self.net['network']['id'])
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 200)

    def test_delete_returns_204(self):
        req = self.new_delete_request('networks', self.net['network']['id'])
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 204)

    def test_update_returns_202(self):
        req = self.new_update_request('networks',
                                      {'network': {'name': 'steve'}},
                                      self.net['network']['id'])
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 202)

    def test_bad_route_404(self):
        req = self.new_list_request('doohickeys')
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 404)


class TestPortsV2(APIv2TestCase):
    def setUp(self):
        super(TestPortsV2, self).setUp()
        res = self._create_network("json", "net1", True)
        data = self._deserializers["application/json"].\
                            deserialize(res.body)["body"]
        self.net_id = data["network"]["id"]

    def _create_port(self, fmt, net_id, admin_state_up, device_id,
                     custom_req_body=None,
                     expected_res_status=None):
        content_type = "application/" + fmt
        data = {'port': {'network_id': net_id,
                         'admin_state_up': admin_state_up,
                         'device_id': device_id}}
        port_req = self.new_create_request('ports', data, fmt)
        port_res = port_req.get_response(self.api)
        return json.loads(port_res.body)

    def test_create_port_json(self):
        port = self._create_port("json", self.net_id, True, "dev_id_1")
        self.assertEqual(port['id'], "dev_id_1")
        self.assertEqual(port['admin_state_up'], "DOWN")
        self.assertEqual(port['device_id'], "dev_id_1")
        self.assertTrue("mac_address" in port)
        self.assertTrue('op_status' in port)

    def test_list_ports(self):
        port1 = self._create_port("json", self.net_id, True, "dev_id_1")
        port2 = self._create_port("json", self.net_id, True, "dev_id_2")

        res = self.new_list_request("ports", "json")
        port_list = json.loads(res.body)["body"]
        self.assertTrue(port1 in port_list["ports"])
        self.assertTrue(port2 in port_list["ports"])

    def test_show_port(self):
        port = self._create_port("json", self.net_id, True, "dev_id_1")
        res = self.new_show_request("port", "json", port["id"])
        port = json.loads(res.body)["body"]
        self.assertEquals(port["port"]["name"], "dev_id_1")

    def test_delete_port(self):
        port = self._create_port("json", self.net_id, True, "dev_id_1")
        self.new_delete_request("port", "json", port["id"])

        port = self.new_show_request("port", "json", port["id"])

        self.assertEquals(res.status_int, 404)

    def test_update_port(self):
        port = self._create_port("json", self.net_id, True, "dev_id_1")
        port_body = {"port": {"device_id": "Bob"}}
        res = self.new_update_request("port", port_body, port["id"])
        port = json.loads(res.body)["body"]
        self.assertEquals(port["device_id"], "Bob")

    def test_delete_non_existent_port_404(self):
        res = self.new_delete_request("port", "json", 1)
        self.assertEquals(res.status_int, 404)

    def test_show_non_existent_port_404(self):
        res = self.new_show_request("port", "json", 1)
        self.assertEquals(res.status_int, 404)

    def test_update_non_existent_port_404(self):
        res = self.new_update_request("port", "json", 1)
        self.assertEquals(res.status_int, 404)


class TestNetworksV2(APIv2TestCase):
    # NOTE(cerberus): successful network update and delete are
    #                 effectively tested above
    def setUp(self):
        super(TestNetworksV2, self).setUp()
        res = self._create_network('json', "net1", True)
        self.net = self.deserialize("json", res)

    def test_create_network(self):
        keys = [('subnets', []), ('name', 'net1'), ('admin_state_up', True),
         ('op_status', 'ACTIVE'), ('tags', [])]
        for k, v in keys:
            self.assertEquals(self.net['network'][k], v)

    def test_list_networks(self):
        req = self.new_list_request('networks')
        res = req.get_response(self.api)
        net = self.deserialize("json", res)
        self.assertEquals(res.status_int, 200)

    def test_show_network(self):
        req = self.new_show_request('networks', self.net['network']['id'])
        res = req.get_response(self.api)
        net = self.deserialize("json", res)
        self.assertEquals(res.status_int, 200)

    def test_update_network_bad_attributes_422(self):
        req = self.new_update_request('networks',
                                      {'network': {}},
                                      self.net['network']['id'])
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 422)


#class TestSubnetsV2(APIv2TestCase):
#    def setUp(self):
#        super(TestSubnetsV2, self).setUp()
#
#    def _subnet_create_request(self, tenant_id, net_id, ip_version, prefix,
#                               gateway_ip, fmt='json'):
#        data = {'subnet': {'network_id': net_id,

#                           'ip_version': ip_version,
#                           'prefix': prefix,
#                           'gateway_ip': gateway_ip
#                          }
#               }
#        return self._create_request(tenant_id, 'subnets', data, fmt)
#
#

#
#    def _test_create_and_show_network(self, fmt):
#        content_type = "application/%s" % fmt
#        net_name = "net1"
#        net_admin_state_up = True
#        net_id = self._create_network(fmt, net_name, net_admin_state_up)
#
#        show_req = self._show_request(self._tenant_id, "networks", net_id, fmt)
#
#        show_res = show_req.get_response(self.api)
#        self.assertEqual(show_res.status_int, 200)
#        network_data = self._deserializers[content_type].\
#                            deserialize(show_res.body)['body']['network']
#        self.assertEqual(network_data['id'], net_id)
#        self.assertEqual(network_data['name'], net_name)
#        self.assertEqual(network_data['admin_state_up'], net_admin_state_up)
#
#    def _test_create_and_list_networks(self, fmt):
#        content_type = "application/%s" % fmt
#        net_name1 = "net1"
#        net_admin_state_up1 = True
#        net_name2 = "net2"
#        net_admin_state_up2 = False
#        net_id1 = self._create_network(fmt, net_name1, net_admin_state_up1)
#        net_id2 = self._create_network(fmt, net_name2, net_admin_state_up2)
#
#        list_req = self._list_request(self._tenant_id, "networks", fmt)
#
#        list_res = list_req.get_response(self.api)
#        self.assertEqual(list_res.status_int, 200)
#        network_list = self._deserializers[content_type].\
#                            deserialize(list_res.body)['body']['networks']
#        self.assertEqual(len(network_list), 2)
#        if network_list[0]['id'] == net_id1:
#            net1_data = network_list[0]
#            net2_data = network_list[1]
#        else:
#            net1_data = network_list[1]
#            net2_data = network_list[0]
#
#        self.assertEqual(net1_data['id'], net_id1)
#        self.assertEqual(net1_data['name'], net_name1)
#        self.assertEqual(net1_data['admin_state_up'], net_admin_state_up1)
#
#        self.assertEqual(net2_data['id'], net_id2)
#        self.assertEqual(net2_data['name'], net_name2)
#        self.assertEqual(net2_data['admin_state_up'], net_admin_state_up2)
#
#    def _test_create_and_delete_network(self, fmt):
#        content_type = "application/%s" % fmt
#        net_id = self._create_network(fmt, "net1", True)
#
#        # confirm create
#        show_req = self._show_request(self._tenant_id, "networks", net_id, fmt)
#
#        show_res = show_req.get_response(self.api)
#        self.assertEqual(show_res.status_int, 200)
#
#        del_req = self._delete_request(self._tenant_id, "networks", net_id,
#                                       fmt)
#
#        del_res = del_req.get_response(self.api)
#        self.assertEqual(del_res.status_int, 204)
#
#        # confirm delete
#        # FIXME(danwent): enable once fault handlers are
#        # implemented
#        #show_req = self._show_request(self._tenant_id, "networks", net_id,
#        #                              fmt)
#
#        #show_res = show_req.get_response(self.api)
#        #self.assertEqual(show_res.status_int, 404)
#
#
#    def test_create_and_show_network_json(self):
#        self._test_create_and_show_network("json")
#
#    def test_create_and_list_networks_json(self):
#        self._test_create_and_list_networks("json")
#
#    def test_create_and_delete_network_json(self):
#        self._test_create_and_delete_network("json")
#
#    def _create_subnet(self, fmt, net_id, ip_version, prefix,
#                       gateway_ip,
#                       custom_req_body=None,
#                       expected_res_status=None):
#        LOG.debug("Creating subnet")
#        content_type = "application/" + fmt
#        subnet_req = self._subnet_create_request(self._tenant_id,
#                                                 net_id, ip_version,
#                                                 prefix, gateway_ip,
#                                                 fmt)
#        subnet_res = subnet_req.get_response(self.api)
#        expected_res_status = expected_res_status or 202
#        self.assertEqual(subnet_res.status_int, expected_res_status)
#        subnet_data = self._deserialize(content_type,
#                                                          subnet_res)
#        return subnet_data['subnet']['id']
#
#    def _test_create_subnet(self, fmt):
#        net_id = self._create_network(fmt, "net1", True)
#        self._create_subnet(fmt, net_id, 4, "10.0.0.0/24", "10.0.0.1")
#
#    def _test_create_and_show_subnet(self, fmt):
#        content_type = "application/%s" % fmt
#
#        net_id = self._create_network(fmt, "net1", True)
#        ip_version = 4
#        prefix = "10.0.0.0/24"
#        gateway_ip = "10.0.0.1"
#        subnet_id = self._create_subnet(fmt, net_id, ip_version, prefix,
#                                        gateway_ip)
#
#        show_req = self._show_request(self._tenant_id, "subnets", subnet_id,
#                                      fmt)
#
#        show_res = show_req.get_response(self.api)
#        self.assertEqual(show_res.status_int, 200)
#        subnet_data = self._deserializers[content_type].\
#                            deserialize(show_res.body)['body']['subnet']
#        self.assertEqual(subnet_data['network_id'], net_id)
#        self.assertEqual(subnet_data['ip_version'], ip_version)
#        self.assertEqual(subnet_data['prefix'], prefix)
#        self.assertEqual(subnet_data['gateway_ip'], gateway_ip)
#
#        # confirm that subnet shows up in network's list of subnets
#        show_req = self._show_request(self._tenant_id, "networks", net_id, fmt)
#        show_res = show_req.get_response(self.api)
#        self.assertEqual(show_res.status_int, 200)
#        net_data = self._deserializers[content_type].\
#                            deserialize(show_res.body)['body']['network']
#        self.assertTrue(subnet_id in net_data['subnets'])
#
#    def _test_create_and_list_subnets(self, fmt):
#        content_type = "application/%s" % fmt
#        subnet_net_id1 = self._create_network(fmt, "net1", True)
#        subnet_ip_version1 = 4
#        subnet_prefix1 = "10.0.1.0/24"
#        subnet_gateway_ip1 = "10.0.1.254"
#        subnet_net_id2 = self._create_network(fmt, "net2", True)
#        subnet_ip_version2 = 6
#        # 2001:0db8:85a3:0000:0000:8a2e:0:0/24
#        subnet_prefix2 = "20.0.0.0/24"
#        #2001:0db8:85a3:0000:0000:8a2e:0:1
#        subnet_gateway_ip2 = "20.0.0.1"
#
#        subnet_id1 = self._create_subnet(fmt, subnet_net_id1,
#                                         subnet_ip_version1, subnet_prefix1,
#                                         subnet_gateway_ip1)
#        subnet_id2 = self._create_subnet(fmt, subnet_net_id2,
#                                         subnet_ip_version2, subnet_prefix2,
#                                         subnet_gateway_ip2)
#
#        list_req = self._list_request(self._tenant_id, "subnets", fmt)
#
#        list_res = list_req.get_response(self.api)
#        self.assertEqual(list_res.status_int, 200)
#        subnet_list = self._deserializers[content_type].\
#                            deserialize(list_res.body)['body']['subnets']
#        self.assertEqual(len(subnet_list), 2)
#        if subnet_list[0]['id'] == subnet_id1:
#            subnet1_data = subnet_list[0]
#            subnet2_data = subnet_list[1]
#        else:
#            subnet1_data = subnet_list[1]
#            subnet2_data = subnet_list[0]
#
#        self.assertEqual(subnet1_data['id'], subnet_id1)
#        self.assertEqual(subnet1_data['network_id'], subnet_net_id1)
#        self.assertEqual(subnet1_data['ip_version'], subnet_ip_version1)
#        self.assertEqual(subnet1_data['prefix'], subnet_prefix1)
#        self.assertEqual(subnet1_data['gateway_ip'], subnet_gateway_ip1)
#
#        self.assertEqual(subnet2_data['id'], subnet_id2)
#        self.assertEqual(subnet2_data['network_id'], subnet_net_id2)
#        self.assertEqual(subnet2_data['ip_version'], subnet_ip_version2)
#        self.assertEqual(subnet2_data['prefix'], subnet_prefix2)
#        self.assertEqual(subnet2_data['gateway_ip'], subnet_gateway_ip2)
#
#    def _test_create_and_delete_subnet(self, fmt):
#        content_type = "application/%s" % fmt
#        net_id = self._create_network(fmt, "subnet1", True)
#        subnet_id = self._create_subnet(fmt, net_id, 4, "9.9.0.0/24",
#                                        "9.9.0.1")
#        show_req = self._show_request(self._tenant_id, "subnets", subnet_id,
#                                      fmt)
#        show_res = show_req.get_response(self.api)
#        self.assertEqual(show_res.status_int, 200)
#
#        del_req = self._delete_request(self._tenant_id, "subnets", subnet_id,
#                                       fmt)
#        del_res = del_req.get_response(self.api)
#        self.assertEqual(del_res.status_int, 204)
#
#        #FIXME(danwent): once fault handler exists, check that we get
#        # a 404 doing a show request.
#
#    def test_create_subnet_json(self):
#        self._test_create_subnet("json")
#
#    def test_create_and_show_subnet_json(self):
#        self._test_create_and_show_subnet("json")
#
#    def test_create_and_list_subnets_json(self):
#        self._test_create_and_list_subnets("json")
#
#    def test_create_and_delete_subnet_json(self):
#        self._test_create_and_delete_subnet("json")
#

