# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.  All rights reserved.
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
# @author: Abhishek Raut, Cisco Systems, Inc.

import httplib
import logging
import base64

from quantum.wsgi import Serializer
from quantum.extensions import providernet as provider
from quantum.plugins.cisco.db import network_db_v2 as cdb
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials_v2 as cred
from quantum.plugins.cisco.common import cisco_exceptions as exc
from quantum.plugins.cisco.extensions import n1kv_profile

LOG = logging.getLogger(__name__)

TENANT = const.NETWORK_ADMIN


class Client(object):
    """
    Client for the Cisco Nexus1000V Quantum Plugin

    This client implements functions to communicate with
    Cisco Nexus1000V VSM.

    For every Quantum objects Cisco Nexus1000V Quantum Plugin
    creates a corresponding object in the controller (Cisco
    Nexus1000V VSM).

    CONCEPTS:

    Following are few concepts used in Nexus1000V VSM

    network-segment:

    Each network-segment represents a broadcast domain

    network-segment-pool:

    A network-segment-pool contains one or more network-segments

    logical-network:

    A logical-network contains one or more network-segment-pool

    vm-network:

    vm-network refers to a network and port-profile
    It also has a list of ports that uses the network and
    port-profile this vm-network refers to.

    WORK FLOW:

    For every network profile a corresponding logical-network and
    network-segment-pool under this logical-network will be created

    For every network created from a given network profile a
    network-segment will be added to that network-segment-pool that
    corresponds to the network profile

    A port uses a network and port-profile. Hence for every unique
    combination of a network and a port-profile a unique vm-network
    will be created, and a reference to the port will be added. If
    the same combination is used by another port, the refernce to
    that port will be added to the same vm-network.


    """

    #Metadata for deserializing xml
    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "network": ["id", "name"],
                "port": ["id", "mac_address"],
                "subnet": ["id", "prefix"]},
            },
            "plurals": {
                "networks": "network",
                "ports": "port",
                "set": "instance",
                "subnets": "subnet", }, }

    # Define paths here
    profiles_path = "/virtual-port-profile"
    network_segments_path = "/vm-network-definition"
    network_segment_path = "/vm-network-definition/%s"
    network_segment_pools_path = "/fabric-network-definition"
    network_segment_pool_path = "/fabric-network-definition/%s"
    ip_pools_path = "/ip-address-pool"
    ip_pool_path = "/ip-address-pool/%s"
    ports_path = "/vm-network/%s/ports"
    port_path = "/vm-network/%s/ports/%s"
    vm_networks_path = "/vm-network"
    vm_network_path = "/vm-network/%s"
    bridge_domains_path = "/bridge-domain"
    bridge_domain_path = "/bridge-domain/%s"
    fabric_networks_path = "/fabric-network"

    def list_profiles(self, **_params):
        """
        Fetches a list of all profiles
        """
        return self._get(self.profiles_path, params=_params)

    def create_bridge_domain(self, network, **_params):
        """
        Creates a Bridge Domain on VSM
        """
        body = {'name': network['name'] + '_bd',
                'segmentId': network[provider.SEGMENTATION_ID],
                'groupIp': network[n1kv_profile.MULTICAST_IP], }
        return self._post(self.bridge_domains_path, body=body, params=_params)

    def delete_bridge_domain(self, name, **_params):
        """
        Deletes a Bridge Domain on VSM
        :param network:
        :param _params:
        :return:
        """
        return self._delete(self.bridge_domain_path % (name))

    def create_network_segment(self, network, profile, **_params):
        """
        Creates a Nework Segment on the VSM
        """
        LOG.debug("seg id %s\n", profile['name'])
        body = {'name': network['name'],
                'id': network['id'],
                'networkDefinition': profile['name'], }
        if network[provider.NETWORK_TYPE] == const.TYPE_VLAN:
            body.update({'vlan': network[provider.SEGMENTATION_ID]})
        if network[provider.NETWORK_TYPE] == const.TYPE_VXLAN:
            body.update({'bridgeDomain': network['name'] + '_bd'})
        return self._post(self.network_segments_path, body=body,
                          params=_params)

    def update_network_segment(self, network_segment, body):
        """
        Updates a Nework Segment on the VSM
        """
        return self._post(self.network_segment_path % (network_segment),
                          body=body)

    def delete_network_segment(self, network_segment, **_params):
        """
        Deletes a Nework Segment on the VSM
        """
        return self._delete(self.network_segment_path % (network_segment))

    def create_fabric_network(self, profile, **_params):
        """
        Creates a Fabric Network on the VSM
        """
        LOG.debug("fabric network")
        body = {'name': profile['name']}
        return self._post(self.fabric_networks_path, body=body, params=_params)

    def create_network_segment_pool(self, profile, **_params):
        """
        Creates a Network Segment Pool on the VSM
        """
        LOG.debug("network_segment_pool")
        body = {'name': profile['name'],
                'id': profile['id'],
                'fabricNetworkName': 'test'}
        return self._post(self.network_segment_pools_path, body=body,
                          params=_params)

    def update_network_segment_pool(self, network_segment_pool, body):
        """
        Updates a Network Segment Pool on the VSM
        """
        return self._post(self.network_segment_pool_path %\
                          (network_segment_pool), body=body)

    def delete_network_segment_pool(self, network_segment_pool, **_params):
        """
        Deletes a Network Segment Pool on the VSM
        """
        return self._delete(self.network_segment_pool_path %\
                            (network_segment_pool))

    def create_ip_pool(self, subnet, **_params):
        """
        Creates an ip-pool on the VSM
        """
        cidr = {'0': '0.0.0.0',
                '1': '128.0.0.0',
                '2': '192.0.0.0',
                '3': '224.0.0.0',
                '4': '240.0.0.0',
                '5': '248.0.0.0',
                '6': '252.0.0.0',
                '7': '254.0.0.0',
                '8': '255.0.0.0',
                '9': '255.128.0.0',
                '10': '255.192.0.0',
                '11': '255.224.0.0',
                '12': '255.240.0.0',
                '13': '255.248.0.0',
                '14': '255.252.0.0',
                '15': '255.254.0.0',
                '16': '255.255.0.0',
                '17': '255.255.128.0',
                '18': '255.255.192.0',
                '19': '255.255.224.0',
                '20': '255.255.240.0',
                '21': '255.255.248.0',
                '22': '255.255.252.0',
                '23': '255.255.254.0',
                '24': '255.255.255.0',
                '25': '255.255.255.128',
                '26': '255.255.255.192',
                '27': '255.255.255.224',
                '28': '255.255.255.240',
                '29': '255.255.255.248',
                '30': '255.255.255.252',
                '31': '255.255.255.254',
                '32': '255.255.255.255',}

        if subnet['cidr']:
            cidr_block = subnet['cidr'].split('/')[1]
            if int(cidr_block) in range(0,32):
                netmask = cidr[cidr_block]
            else:
                netmask = ''
        else:
            netmask = ''

        if subnet['allocation_pools']:
            address_range_start = subnet['allocation_pools'][0]['start']
            address_range_end   = subnet['allocation_pools'][0]['end']
        else:
            address_range_start = None
            address_range_end   = None

        body = {'dhcp': subnet['enable_dhcp'],
                'addressRangeStart': address_range_start,
                'addressRangeEnd': address_range_end,
                'ipAddressSubnet': netmask,
                'name': subnet['name'],
                'gateway': subnet['gateway_ip'], }
        return self._post(self.ip_pools_path, body=body, params=_params)

    def delete_ip_pool(self, subnet_name):
        """
        Deletes an ip-pool on the VSM
        """
        return self._delete(self.ip_pool_path % (subnet_name))

    # TODO: Removing tenantId from the request as a temp fix to allow 
    #       port create. VSM CLI needs to be fixed. Should not interfere
    #       since VSM is not using tenantId as of now.
    def create_vm_network(self, port, name, policy_profile, **_params):
        """
        Creates a VM Network on the VSM
        :param port:
        :param name:
        :param policy_profile:
        :return:
        """
        body = {'name': name,
                #'tenantId': port['tenant_id'],
                'vmNetworkDefinition': port['network_id'],
                'portProfile': policy_profile['name'],
                'portProfileId': policy_profile['id'],
                }
        return self._post(self.vm_networks_path, body=body, params=_params)

    def delete_vm_network(self, vm_network_name):
        """
        Deletes a VM Network on the VSM
        :param vm_network_name:
        :return:
        """
        return self._delete(self.vm_network_path % (vm_network_name))

    def create_n1kv_port(self, port, name, **_params):
        """
        Creates a Port on the VSM
        """
        body = {'id': port['id'],
                'macAddress': port['mac_address']}
        return self._post(self.ports_path % (name), body=body, params=_params)

    def update_n1kv_port(self, vm_network_name, port_id, body):
        """
        Updates a Port on the VSM
        """
        return self._post(self.port_path % ((vm_network_name), (port_id)), body=body)

    def delete_n1kv_port(self, vm_network_name, port_id, **_params):
        """
        Deletes a Port on the VSM
        """
        return self._delete(self.port_path % ((vm_network_name), (port_id)))

    def __init__(self, **kwargs):
        """ Initialize a new client for the Plugin v2.0. """
        self.format = 'json'
        self.action_prefix = '/api/hyper-v'
        self.hosts = self._get_vsm_hosts(TENANT)

    def _handle_fault_response(self, status_code, replybody):
        if status_code == httplib.INTERNAL_SERVER_ERROR:
            raise exc.VSMError(reason=_(replybody))
        elif status_code == httplib.SERVICE_UNAVAILABLE:
            raise exc.VSMConnectionFailed

    def _do_request(self, method, action, body=None,
                    headers=None, params=None):
        """
        Perform the HTTP request
        """
        action = self.action_prefix + action
        if headers is None  and  self.hosts:
            headers = self._get_header(self.hosts[0])
        if body:
            body = self._serialize(body)
            body = body + '  '
            LOG.debug("req: %s", body)
        conn = httplib.HTTPConnection(self.hosts[0])
        conn.request(method, action, body, headers)
        resp = conn.getresponse()
        _content_type = resp.getheader('content-type')
        replybody = resp.read()
        status_code = self._get_status_code(resp)
        LOG.debug("status_code %s\n", status_code)
        if status_code == httplib.OK and 'application/xml' in _content_type:
            return self._deserialize(replybody, status_code)
        elif status_code == httplib.OK and 'text/plain' in _content_type:
            LOG.debug("VSM: %s", replybody)
        elif status_code in (httplib.INTERNAL_SERVER_ERROR,
                             httplib.NOT_FOUND,
                             httplib.SERVICE_UNAVAILABLE):
            self._handle_fault_response(status_code, replybody)

    def _get_status_code(self, response):
        """
        Returns the integer status code from the response, which
        can be either a Webob.Response (used in testing) or httplib.Response
        """
        if hasattr(response, 'status_int'):
            return response.status_int
        else:
            return response.status

    def _serialize(self, data):
        """
        Serializes a dictionary with a single key (which can contain any
        structure) into either xml or json
        """
        if data is None:
            return None
        elif type(data) is dict:
            return Serializer().serialize(data, self._set_content_type())
        else:
            raise Exception("unable to serialize object of type = '%s'" %
                            type(data))

    def _deserialize(self, data, status_code):
        """
        Deserializes an xml string into a dictionary
        """
        if status_code == 204:
            return data
        return Serializer(self._serialization_metadata).deserialize(
                          data, self._set_content_type('xml'))

    def _set_content_type(self, format=None):
        """
        Returns the mime-type for either 'xml' or 'json'.  Defaults to the
        currently set format
        """
        if not format:
            format = self.format
        return "application/%s" % (format)

    def _delete(self, action, body=None, headers=None, params=None):
        return self._do_request("DELETE", action, body=body,
                               headers=headers, params=params)

    def _get(self, action, body=None, headers=None, params=None):
        return self._do_request("GET", action, body=body,
                                  headers=headers, params=params)

    def _post(self, action, body=None, headers=None, params=None):
        return self._do_request("POST", action, body=body,
                               headers=headers, params=params)

    def _put(self, action, body=None, headers=None, params=None):
        return self._do_request("PUT", action, body=body,
                                  headers=headers, params=params)

    def _get_vsm_hosts(self, tenant_id):
        """
        Returns a list of VSM ip addresses.
        CREDENTIAL_NAME in the credentials object corresponds to an
        ip address.
        """
        host_list = []
        credentials = cdb.get_all_n1kv_credentials()
        for cr in credentials:
            host_list.append(cr[const.CREDENTIAL_NAME])
        return host_list

    def _get_header(self, host_ip):
        """
        Returns a header with auth info for the VSM
        """
        username = cred.Store.get_username(host_ip)
        password = cred.Store.get_password(host_ip)
        auth = base64.encodestring("%s:%s" % (username, password))
        headers = {"Authorization": "Basic %s" % auth,
                   "Content-Type": "application/json"}
        return headers
