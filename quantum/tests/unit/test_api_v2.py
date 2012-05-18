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

class APIv2Test(unittest.TestCase):

    api = APIRouter({ "plugin_provider":
                    "quantum.db.database_plugin_v2.QuantumDBPlugin_V2" })

    def setUp(self):
        super(APIv2Test, self).setUp()
        self._tenant_id = "test-tenant"

        json_deserializer = JSONDeserializer()
        self._deserializers = {
            'application/json': json_deserializer,
        }

    def tearDown(self):
        """Clear the test environment"""
        #TODO(danwent): this should be a generic call to the
        # plugin to clear state...
        QuantumManager.get_plugin().clear_state()

    def _network_create_request(self, tenant_id, name, admin_status_up,
                                format='xml'):
        data = {'network': {'name': name,
                            'admin_state_up': admin_status_up,
                           }
               }
        return self._create_request(tenant_id, 'networks', data, format)

    def _subnet_create_request(self, tenant_id, net_id, ip_version, prefix,
                               gateway_ip, format='xml'):
        data = {'subnet': {'network_id': net_id,
                           'ip_version': ip_version,
                           'prefix': prefix,
                           'gateway_ip': gateway_ip
                          }
               }
        return self._create_request(tenant_id, 'subnets', data, format)

    def _port_create_request(self, tenant_id, net_id, admin_state_up,
                             device_id, format='xml'):
        data = {'port': {'network_id': net_id,
                         'admin_state_up': admin_state_up,
                         'device_id': device_id
                        }
               }
        return self._create_request(tenant_id, 'ports', data, format)

    def _create_request(self, tenant_id, resource, data, format='xml'):
        method = 'POST'
        path = ("/%(resource)s.%(format)s") % locals()
        content_type = "application/%s" % format
        body = Serializer().serialize(data, content_type)
        return create_request(path, body, content_type, method)

    def _list_request(self, tenant_id, resource, format='xml'):
        method = 'GET'
        path = ("/%(resource)s.%(format)s") % locals()
        content_type = "application/%s" % format
        return create_request(path, None, content_type, method)

    def _show_request(self, tenant_id, resource, id, format='xml'):
        method = 'GET'
        path = ("/%(resource)s/%(id)s.%(format)s") % locals()
        content_type = "application/%s" % format
        return create_request(path, None, content_type, method)

    def _delete_request(self, tenant_id, resource, id, format='xml'):
        method = 'DELETE'
        path = ("/%(resource)s/%(id)s.%(format)s") % locals()
        content_type = "application/%s" % format
        return create_request(path, None, content_type, method)

    def _deserialize_response(self, content_type, response):
        data = self._deserializers[content_type].\
                            deserialize(response.body)['body']
        # do not taint assertions with xml namespace
        top_key = data.keys()[0]
        if 'xmlns' in data[top_key]:
            del data[top_key]['xmlns']
        return data

    def _create_network(self, fmt, name, admin_status_up,
                        custom_req_body=None,
                        expected_res_status=None):
        LOG.debug("Creating network")
        content_type = "application/" + fmt
        network_req = self._network_create_request(self._tenant_id,
                                                 name,
                                                 admin_status_up,
                                                 fmt)
        network_res = network_req.get_response(self.api)
        expected_res_status = expected_res_status or 202
        self.assertEqual(network_res.status_int, expected_res_status)
        network_data = self._deserialize_response(content_type,
                                                          network_res)
        return network_data['network']['id']

    def _test_create_network(self, fmt):
        self._create_network(fmt, "net1", True)

    def _test_create_and_show_network(self, fmt):
        content_type = "application/%s" % fmt
        net_name = "net1"
        net_admin_state_up = True
        net_id = self._create_network(fmt, net_name, net_admin_state_up)

        show_req = self._show_request(self._tenant_id, "networks", net_id, fmt)

        show_res = show_req.get_response(self.api)
        self.assertEqual(show_res.status_int, 200)
        network_data = self._deserializers[content_type].\
                            deserialize(show_res.body)['body']['network']
        self.assertEqual(network_data['id'], net_id)
        self.assertEqual(network_data['name'], net_name)
        self.assertEqual(network_data['admin_state_up'], net_admin_state_up)

    def _test_create_and_list_networks(self, fmt):
        content_type = "application/%s" % fmt
        net_name1 = "net1"
        net_admin_state_up1 = True
        net_name2 = "net2"
        net_admin_state_up2 = False
        net_id1 = self._create_network(fmt, net_name1, net_admin_state_up1)
        net_id2 = self._create_network(fmt, net_name2, net_admin_state_up2)

        list_req = self._list_request(self._tenant_id, "networks", fmt)

        list_res = list_req.get_response(self.api)
        self.assertEqual(list_res.status_int, 200)
        network_list = self._deserializers[content_type].\
                            deserialize(list_res.body)['body']['networks']
        self.assertEqual(len(network_list), 2)
        if network_list[0]['id'] == net_id1:
            net1_data = network_list[0]
            net2_data = network_list[1]
        else:
            net1_data = network_list[1]
            net2_data = network_list[0]

        self.assertEqual(net1_data['id'], net_id1)
        self.assertEqual(net1_data['name'], net_name1)
        self.assertEqual(net1_data['admin_state_up'], net_admin_state_up1)

        self.assertEqual(net2_data['id'], net_id2)
        self.assertEqual(net2_data['name'], net_name2)
        self.assertEqual(net2_data['admin_state_up'], net_admin_state_up2)

    def _test_create_and_delete_network(self, fmt):
        content_type = "application/%s" % fmt
        net_id = self._create_network(fmt, "net1", True)

        # confirm create
        show_req = self._show_request(self._tenant_id, "networks", net_id, fmt)

        show_res = show_req.get_response(self.api)
        self.assertEqual(show_res.status_int, 200)

        del_req = self._delete_request(self._tenant_id, "networks", net_id, fmt)

        del_res = del_req.get_response(self.api)
        self.assertEqual(del_res.status_int, 204)

        # confirm delete
        # FIXME(danwent): enable once fault handlers are
        # implemented
        #show_req = self._show_request(self._tenant_id, "networks", net_id, fmt)

        #show_res = show_req.get_response(self.api)
        #self.assertEqual(show_res.status_int, 404)

    def test_create_network_json(self):
        self._test_create_network("json")

    def test_create_and_show_network_json(self):
        self._test_create_and_show_network("json")

    def test_create_and_list_networks_json(self):
        self._test_create_and_list_networks("json")

    def test_create_and_delete_network_json(self):
        self._test_create_and_delete_network("json")

    def _create_subnet(self, fmt, net_id, ip_version, prefix,
                       gateway_ip,
                       custom_req_body=None,
                       expected_res_status=None):
        LOG.debug("Creating subnet")
        content_type = "application/" + fmt
        subnet_req = self._subnet_create_request(self._tenant_id,
                                                 net_id, ip_version,
                                                 prefix, gateway_ip,
                                                 fmt)
        subnet_res = subnet_req.get_response(self.api)
        expected_res_status = expected_res_status or 202
        self.assertEqual(subnet_res.status_int, expected_res_status)
        subnet_data = self._deserialize_response(content_type,
                                                          subnet_res)
        return subnet_data['subnet']['id']

    def _test_create_subnet(self, fmt):
        net_id = self._create_network(fmt, "net1", True)
        self._create_subnet(fmt, net_id, 4, "10.0.0.0/24", "10.0.0.1")

    def _test_create_and_show_subnet(self, fmt):
        content_type = "application/%s" % fmt

        net_id = self._create_network(fmt, "net1", True)
        ip_version = 4
        prefix = "10.0.0.0/24"
        gateway_ip = "10.0.0.1"
        subnet_id = self._create_subnet(fmt, net_id, ip_version, prefix,
                                        gateway_ip)

        show_req = self._show_request(self._tenant_id, "subnets", subnet_id, fmt)

        show_res = show_req.get_response(self.api)
        self.assertEqual(show_res.status_int, 200)
        subnet_data = self._deserializers[content_type].\
                            deserialize(show_res.body)['body']['subnet']
        self.assertEqual(subnet_data['network_id'], net_id)
        self.assertEqual(subnet_data['ip_version'], ip_version)
        self.assertEqual(subnet_data['prefix'], prefix)
        self.assertEqual(subnet_data['gateway_ip'], gateway_ip)

        # confirm that subnet shows up in network's list of subnets
        show_req = self._show_request(self._tenant_id, "networks", net_id, fmt)
        show_res = show_req.get_response(self.api)
        self.assertEqual(show_res.status_int, 200)
        net_data = self._deserializers[content_type].\
                            deserialize(show_res.body)['body']['network']
        self.assertTrue(subnet_id in net_data['subnets'])


    def _test_create_and_list_subnets(self, fmt):
        content_type = "application/%s" % fmt
        subnet_net_id1 = self._create_network(fmt, "net1", True)
        subnet_ip_version1 = 4
        subnet_prefix1 = "10.0.1.0/24"
        subnet_gateway_ip1 = "10.0.1.254"
        subnet_net_id2 = self._create_network(fmt, "net2", True)
        subnet_ip_version2 = 6
        subnet_prefix2 = "20.0.0.0/24" #"2001:0db8:85a3:0000:0000:8a2e:0:0/24"
        subnet_gateway_ip2 = "20.0.0.1" #"2001:0db8:85a3:0000:0000:8a2e:0:1"

        subnet_id1 = self._create_subnet(fmt, subnet_net_id1, subnet_ip_version1,
                                         subnet_prefix1, subnet_gateway_ip1)
        subnet_id2 = self._create_subnet(fmt, subnet_net_id2, subnet_ip_version2,
                                         subnet_prefix2, subnet_gateway_ip2)

        list_req = self._list_request(self._tenant_id, "subnets", fmt)

        list_res = list_req.get_response(self.api)
        self.assertEqual(list_res.status_int, 200)
        subnet_list = self._deserializers[content_type].\
                            deserialize(list_res.body)['body']['subnets']
        self.assertEqual(len(subnet_list), 2)
        if subnet_list[0]['id'] == subnet_id1:
            subnet1_data = subnet_list[0]
            subnet2_data = subnet_list[1]
        else:
            subnet1_data = subnet_list[1]
            subnet2_data = subnet_list[0]

        self.assertEqual(subnet1_data['id'], subnet_id1)
        self.assertEqual(subnet1_data['network_id'], subnet_net_id1)
        self.assertEqual(subnet1_data['ip_version'], subnet_ip_version1)
        self.assertEqual(subnet1_data['prefix'], subnet_prefix1)
        self.assertEqual(subnet1_data['gateway_ip'], subnet_gateway_ip1)

        self.assertEqual(subnet2_data['id'], subnet_id2)
        self.assertEqual(subnet2_data['network_id'], subnet_net_id2)
        self.assertEqual(subnet2_data['ip_version'], subnet_ip_version2)
        self.assertEqual(subnet2_data['prefix'], subnet_prefix2)
        self.assertEqual(subnet2_data['gateway_ip'], subnet_gateway_ip2)


    def _test_create_and_delete_subnet(self, fmt):
        content_type = "application/%s" % fmt
        net_id = self._create_network(fmt, "subnet1", True)
        subnet_id = self._create_subnet(fmt, net_id, 4, "9.9.0.0/24", "9.9.0.1")

        show_req = self._show_request(self._tenant_id, "subnets", subnet_id, fmt)
        show_res = show_req.get_response(self.api)
        self.assertEqual(show_res.status_int, 200)

        del_req = self._delete_request(self._tenant_id, "subnets", subnet_id, fmt)

        del_res = del_req.get_response(self.api)
        self.assertEqual(del_res.status_int, 204)

        #FIXME(danwent): once fault handler exists, check that we get
        # a 404 doing a show request.

    def test_create_subnet_json(self):
        self._test_create_subnet("json")

    def test_create_and_show_subnet_json(self):
        self._test_create_and_show_subnet("json")

    def test_create_and_list_subnets_json(self):
        self._test_create_and_list_subnets("json")

    def test_create_and_delete_subnet_json(self):
        self._test_create_and_delete_subnet("json")

    def _create_port(self, fmt, net_id, admin_state_up, device_id,
                       custom_req_body=None,
                       expected_res_status=None):
        LOG.debug("Creating port")
        content_type = "application/" + fmt
        port_req = self._port_create_request(self._tenant_id, net_id,
                                             admin_state_up, device_id,
                                             fmt)
        port_res = port_req.get_response(self.api)
        expected_res_status = expected_res_status or 202
        self.assertEqual(port_res.status_int, expected_res_status)
        port_data = self._deserialize_response(content_type, port_res)
        return port_data['port']['id']

    def _test_create_port(self, fmt):
        net_id = self._create_network(fmt, "net1", True)

        self._create_subnet(fmt, net_id, 4, "10.0.0.0/24", "10.0.0.1")
        self._create_port(fmt, net_id, True, "dev_id_1")

    def _test_create_and_show_port(self, fmt):
        content_type = "application/%s" % fmt
        prefix = "10.0.0.0/24"
        iprange = netaddr.IPNetwork(prefix)
        net_id = self._create_network(fmt, "net1", True)
        self._create_subnet(fmt, net_id, 4, prefix, "10.0.0.1")
        dev_id1 = "dev_id_1"
        admin_state_up = True
        port_id = self._create_port(fmt, net_id, admin_state_up, dev_id1)

        show_req = self._show_request(self._tenant_id, "ports", port_id, fmt)

        show_res = show_req.get_response(self.api)
        self.assertEqual(show_res.status_int, 200)
        port_data = self._deserializers[content_type].\
                            deserialize(show_res.body)['body']['port']
        self.assertEqual(port_data['id'], port_id)
        self.assertEqual(port_data['admin_state_up'], admin_state_up)
        self.assertEqual(port_data['device_id'], dev_id1)
        self.assertTrue("mac_address" in port_data)
        self.assertTrue('op_status' in port_data)
        ips = port_data['fixed_ips']
        self.assertEqual(len(ips), 1)
        self.assertTrue(ips[0]['address'] in [ str(x) for x in iprange])


    def _test_create_and_list_ports(self, fmt):
        content_type = "application/%s" % fmt
        prefix1 = "10.0.0.0/24"
        net_id1 = self._create_network(fmt, "net1", True)
        subnet_id1 = self._create_subnet(fmt, net_id1, 4, prefix1, "10.0.0.1")
        device_id1 = "device1"
        admin_state_up1 = False

        prefix2 = "20.0.0.0/24"
        net_id2 = self._create_network(fmt, "net2", True)
        subnet_id2 = self._create_subnet(fmt, net_id2, 4, prefix2, "20.0.0.1")
        device_id2 = "device2"
        admin_state_up2 = True

        port_id1 = self._create_port(fmt, net_id1, admin_state_up1, device_id1)
        port_id2 = self._create_port(fmt, net_id2, admin_state_up2, device_id2)

        list_req = self._list_request(self._tenant_id, "ports", fmt)

        list_res = list_req.get_response(self.api)
        self.assertEqual(list_res.status_int, 200)
        port_list = self._deserializers[content_type].\
                            deserialize(list_res.body)['body']['ports']
        self.assertEqual(len(port_list), 2)
        if port_list[0]['id'] == port_id1:
            port1_data = port_list[0]
            port2_data = port_list[1]
        else:
            port1_data = port_list[1]
            port2_data = port_list[0]

        self.assertEqual(port1_data['id'], port_id1)
        self.assertEqual(port1_data['network_id'], net_id1)
        self.assertEqual(port1_data['admin_state_up'], admin_state_up1)
        self.assertEqual(port1_data['device_id'], device_id1)
        self.assertTrue('mac_address' in port1_data)
        iprange1 = [ str(x) for x in netaddr.IPNetwork(prefix1)]
        self.assertTrue(port1_data['fixed_ips'][0]['address'] in iprange1)
        self.assertEqual(port1_data['fixed_ips'][0]['subnet_id'], subnet_id1)

        self.assertEqual(port2_data['id'], port_id2)
        self.assertEqual(port2_data['network_id'], net_id2)
        self.assertEqual(port2_data['admin_state_up'], admin_state_up2)
        self.assertEqual(port2_data['device_id'], device_id2)
        self.assertTrue('mac_address' in port2_data)
        iprange2 = [ str(x) for x in netaddr.IPNetwork(prefix2)]
        self.assertTrue(port2_data['fixed_ips'][0]['address'] in iprange2)
        self.assertEqual(port2_data['fixed_ips'][0]['subnet_id'], subnet_id2)


    def _test_create_and_delete_port(self, fmt):
        content_type = "application/%s" % fmt
        net_id = self._create_network(fmt, "net1", True)
        subnet_id = self._create_subnet(fmt, net_id, 4, "20.0.0.0/24", "20.0.0.1")
        port_id = self._create_port(fmt, net_id, True, "mydevice")

        show_req = self._show_request(self._tenant_id, "ports", port_id, fmt)
        show_res = show_req.get_response(self.api)
        self.assertEqual(show_res.status_int, 200)

        del_req = self._delete_request(self._tenant_id, "ports", port_id, fmt)

        del_res = del_req.get_response(self.api)
        self.assertEqual(del_res.status_int, 204)

        #FIXME(danwent): once fault handler exists, check that we get
        # a 404 doing a show request.

    def test_create_port_json(self):
        self._test_create_port("json")

    def test_create_and_show_port_json(self):
        self._test_create_and_show_port("json")

    def test_create_and_list_ports_json(self):
        self._test_create_and_list_ports("json")

    def test_create_and_delete_port_json(self):
        self._test_create_and_delete_port("json")

