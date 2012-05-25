#import json
import logging
import unittest
#from webob import exc
#import netaddr

from quantum.api.v2.router import APIRouter
#from quantum.manager import QuantumManager
from quantum.tests.unit.testlib_api import create_request
#from quantum.wsgi import Serializer, XMLDeserializer, JSONDeserializer
from quantum.wsgi import Serializer, JSONDeserializer


LOG = logging.getLogger("quantum.tests.api_v2_test")


class APIv2TestCase(unittest.TestCase):
    def setUp(self):
        super(APIv2TestCase, self).setUp()
        self._tenant_id = "test-tenant"

        json_deserializer = JSONDeserializer()
        self._deserializers = {
            "application/json": json_deserializer,
        }

        plugin = "quantum.plugins.sample.SamplePluginV2.FakePlugin"
        self.api = APIRouter({"plugin_provider": plugin})

    def _req(self, method, resource, data=None, fmt="json", id=None):
        if id:
            path = "/%(resource)s/%(id)s.%(fmt)s" % locals()
        else:
            path = "/%(resource)s.%(fmt)s" % locals()
        content_type = "application/%s" % fmt
        body = None
        if data:
            body = Serializer().serialize(data, content_type)
        return create_request(path, body, content_type, method)

    # Yeah, they"re factories. And you better be ok with it.
    # NOTE(BOOM) OMG, the explosion!!!
    def new_create_request(self, resource, data, fmt="json"):
        return self._req("POST", resource, data, fmt)

    def new_list_request(self, resource, fmt="json"):
        return self._req("GET", resource, None, fmt)

    def new_show_request(self, resource, id, fmt="json"):
        return self._req("GET", resource, None, fmt, id=id)

    def new_delete_request(self, resource, id, fmt="json"):
        return self._req("DELETE", resource, None, fmt, id=id)

    def new_update_request(self, resource, data, id, fmt="json"):
        return self._req("PUT", resource, data, fmt, id=id)

    def deserialize(self, content_type, response):
        ctype = "application/%s" % content_type
        data = self._deserializers[ctype].\
                            deserialize(response.body)["body"]
        return data

    def _create_network(self, fmt, name, admin_status_up):
        LOG.debug("Creating network")
        data = {"network": {"name": name,
                            "admin_state_up": admin_status_up}}
        network_req = self.new_create_request("networks", data, fmt)
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
        res = self._create_network("json", "net2", True)
        self.assertEquals(res.status_int, 201)

    def test_list_returns_200(self):
        req = self.new_list_request("networks")
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 200)

    def test_show_returns_200(self):
        req = self.new_show_request("networks", self.net["network"]["id"])
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 200)

    def test_delete_returns_204(self):
        req = self.new_delete_request("networks", self.net["network"]["id"])
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 204)

    def test_update_returns_202(self):
        req = self.new_update_request("networks",
                                      {"network": {"name": "steve"}},
                                      self.net["network"]["id"])
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 202)

    def test_bad_route_404(self):
        req = self.new_list_request("doohickeys")
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 404)

# TODO(cerberus): uncomment once we figure out a way to control the
#                 IP Allocations
#class TestPortsV2(APIv2TestCase):
#    def setUp(self):
#        super(TestPortsV2, self).setUp()
#        res = self._create_network("json", "net1", True)
#        data = self._deserializers["application/json"].\
#                            deserialize(res.body)["body"]
#        self.net_id = data["network"]["id"]
#
#    def _create_port(self, fmt, net_id, admin_state_up, device_id,
#                     custom_req_body=None,
#                     expected_res_status=None):
#        content_type = "application/" + fmt
#        data = {"port": {"network_id": net_id,
#                         "admin_state_up": admin_state_up,
#                         "device_id": device_id}}
#        port_req = self.new_create_request("ports", data, fmt)
#        port_res = port_req.get_response(self.api)
#        return json.loads(port_res.body)
#
#    def test_create_port_json(self):
#        port = self._create_port("json", self.net_id, True, "dev_id_1")
#        self.assertEqual(port["id"], "dev_id_1")
#        self.assertEqual(port["admin_state_up"], "DOWN")
#        self.assertEqual(port["device_id"], "dev_id_1")
#        self.assertTrue("mac_address" in port)
#        self.assertTrue("op_status" in port)
#
#    def test_list_ports(self):
#        port1 = self._create_port("json", self.net_id, True, "dev_id_1")
#        port2 = self._create_port("json", self.net_id, True, "dev_id_2")
#
#        res = self.new_list_request("ports", "json")
#        port_list = json.loads(res.body)["body"]
#        self.assertTrue(port1 in port_list["ports"])
#        self.assertTrue(port2 in port_list["ports"])
#
#    def test_show_port(self):
#        port = self._create_port("json", self.net_id, True, "dev_id_1")
#        res = self.new_show_request("port", "json", port["id"])
#        port = json.loads(res.body)["body"]
#        self.assertEquals(port["port"]["name"], "dev_id_1")
#
#    def test_delete_port(self):
#        port = self._create_port("json", self.net_id, True, "dev_id_1")
#        self.new_delete_request("port", "json", port["id"])
#
#        port = self.new_show_request("port", "json", port["id"])
#
#        self.assertEquals(res.status_int, 404)
#
#    def test_update_port(self):
#        port = self._create_port("json", self.net_id, True, "dev_id_1")
#        port_body = {"port": {"device_id": "Bob"}}
#        res = self.new_update_request("port", port_body, port["id"])
#        port = json.loads(res.body)["body"]
#        self.assertEquals(port["device_id"], "Bob")
#
#    def test_delete_non_existent_port_404(self):
#        res = self.new_delete_request("port", "json", 1)
#        self.assertEquals(res.status_int, 404)
#
#    def test_show_non_existent_port_404(self):
#        res = self.new_show_request("port", "json", 1)
#        self.assertEquals(res.status_int, 404)
#
#    def test_update_non_existent_port_404(self):
#        res = self.new_update_request("port", "json", 1)
#        self.assertEquals(res.status_int, 404)


class TestNetworksV2(APIv2TestCase):
    # NOTE(cerberus): successful network update and delete are
    #                 effectively tested above
    def setUp(self):
        super(TestNetworksV2, self).setUp()
        res = self._create_network("json", "net1", True)
        self.net = self.deserialize("json", res)

    def tearDown(self):
        super(TestNetworksV2, self).setUp()
        req = self.new_delete_request("networks", self.net["network"]["id"])
        req.get_response(self.api)

    def test_create_network(self):
        keys = [("subnets", []), ("name", "net1"), ("admin_state_up", True),
                ("op_status", "ACTIVE"), ("tags", [])]
        for k, v in keys:
            self.assertEquals(self.net["network"][k], v)

    def test_list_networks(self):
        net2 = self.deserialize("json",
                                self._create_network("json", "net2", True))
        req = self.new_list_request("networks")
        res = req.get_response(self.api)
        net = self.deserialize("json", res)
        self.assertEquals(net["networks"][0]["network"]["name"], "net1")
        self.assertEquals(net["networks"][1]["network"]["name"], "net2")
        self.new_delete_request("networks", net2["network"]["id"])

    def test_show_network(self):
        req = self.new_show_request("networks", self.net["network"]["id"])
        res = req.get_response(self.api)
        net = self.deserialize("json", res)
        self.assertEquals(net["network"]["name"], "net1")

    def test_update_network_bad_attributes_422(self):
        req = self.new_update_request("networks",
                                      {"network": {}},
                                      self.net["network"]["id"])
        res = req.get_response(self.api)
        self.assertEquals(res.status_int, 422)


class TestSubnetsV2(APIv2TestCase):
    def setUp(self):
        super(TestSubnetsV2, self).setUp()
        res = self._create_network("json", "net1", True)
        self.net = self.deserialize("json", res)
        res = self._create_subnet("json", self.net["network"]["id"],
                                  "10.0.0.1", "10.0.0.0/24")
        self.subnet = self.deserialize("json", res)

    def tearDown(self):
        req = self.new_delete_request("networks", self.net["network"]["id"])
        req.get_response(self.api)
        req = self.new_delete_request("subnets", self.subnet["subnet"]["id"])
        req.get_response(self.api)

    def _create_subnet(self, fmt, net_id, gateway_ip, prefix):
        #content_type = "application/" + fmt
        data = {"subnet": {"network_id": net_id,
                           "allocations": [],
                           "prefix": prefix,
                           "ip_version": 4,
                           "gateway_ip": gateway_ip}}
        subnet_req = self.new_create_request("subnets", data, fmt)
        return subnet_req.get_response(self.api)

    def test_create_subnet(self):
        keys = [("ip_version", 4), ("gateway_ip", "10.0.0.1"),
                ("prefix", "10.0.0.0/24")]
        for k, v in keys:
            self.assertEquals(self.subnet["subnet"][k], v)

    def test_update_subnet(self):
        req = self.new_update_request("subnets",
                                      {"subnet": {"prefix": "192.168.0.0/24"}},
                                      self.subnet["subnet"]["id"])
        res = req.get_response(self.api)
        subnet = self.deserialize("json", res)
        self.assertEqual(subnet["subnet"]["prefix"], "192.168.0.0/24")

    def test_show_subnet(self):
        req = self.new_show_request("subnets", self.subnet["subnet"]["id"])
        res = req.get_response(self.api)
        net = self.deserialize("json", res)
        self.assertEquals(net["subnet"]["network_id"],
                          self.net["network"]["id"])

    def test_list_subnets(self):
        res = self._create_subnet("json", self.net["network"]["id"],
                                      "10.0.1.1", "10.0.1.0/24")
        subnet2 = self.deserialize("json", res)

        req = self.new_list_request("subnets")
        res = req.get_response(self.api)
        net = self.deserialize("json", res)
        self.assertEquals(net["subnets"][0]["subnet"]["prefix"], "10.0.0.0/24")
        self.assertEquals(net["subnets"][1]["subnet"]["prefix"], "10.0.1.0/24")
        self.new_delete_request("subnets", subnet2["subnet"]["id"])
