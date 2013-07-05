# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cisco Systems, Inc.
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
# @author: Rudrajit Tapadar, Cisco Systems, Inc.

import base64
import httplib

from quantum.extensions import providernet
from quantum.openstack.common import log as logging
from quantum.plugins.cisco.common import cisco_constants
from quantum.plugins.cisco.common import cisco_credentials_v2 as c_cred
from quantum.plugins.cisco.common import cisco_exceptions as c_exc
from quantum.plugins.cisco.db import network_db_v2
from quantum.plugins.cisco.extensions import n1kv_profile
from quantum.wsgi import Serializer

LOG = logging.getLogger(__name__)


class Client(object):

    """
    Client for the Cisco Nexus1000V Quantum Plugin

    This client implements functions to communicate with
    Cisco Nexus1000V VSM.

    For every Quantum objects, Cisco Nexus1000V Quantum Plugin
    creates a corresponding object in the controller (Cisco
    Nexus1000V VSM).

    CONCEPTS:

    Following are few concepts used in Nexus1000V VSM:

    port-profiles:
    Policy profiles correspond to port profiles on Nexus1000V VSM.
    Port profiles are the primary mechanism by which network policy is
    defined and applied to switch interfaces in a Nexus 1000V system.

    network-segment:
    Each network-segment represents a broadcast domain.

    network-segment-pool:
    A network-segment-pool contains one or more network-segments.

    logical-network:
    A logical-network contains one or more network-segment-pools.

    bridge-domain:
    A bridge-domain is created when the network-segment is of type VXLAN.
    Each VXLAN <--> VLAN combination can be thought of as a bridge domain.

    ip-pool:
    Each ip-pool represents a subnet on the Nexus1000V VSM.

    vm-network:
    vm-network refers to a network-segment and policy-profile.
    It maintains a list of ports that uses the network-segment and
    policy-profile this vm-network refers to.

    events:
    Events correspond to commands that are logged on Nexus1000V VSM.
    Events are used to poll for a certain resource on Nexus1000V VSM.
    Event type of port_profile: Return all updates/create/deletes
    of port profiles from the VSM.
    Event type of port_profile_update: Return only updates regarding
    policy-profiles.
    Event type of port_profile_delete: Return only deleted policy profiles.


    WORK FLOW:

    For every network profile a corresponding logical-network and
    a network-segment-pool, under this logical-network, will be created.

    For every network created from a given network profile, a
    network-segment will be added to the network-segment-pool corresponding
    to that network profile.

    A port is created on a network and associated with a policy-profile.
    Hence for every unique combination of a network and a policy-profile, a
    unique vm-network will be created and a reference to the port will be
    added. If the same combination of network and policy-profile is used by
    another port, the refernce to that port will be added to the same
    vm-network.


    """

    # Metadata for deserializing xml
    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "network": ["id", "name"],
                "port": ["id", "mac_address"],
                "subnet": ["id", "prefix"]
            },
        },
        "plurals": {
            "networks": "network",
            "ports": "port",
            "set": "instance",
            "subnets": "subnet"
        }
    }

    # Define paths for the URI where the client connects for HTTP requests.
    port_profiles_path = "/virtual-port-profile"
    network_segments_path = "/vm-network-definition"
    network_segment_path = "/vm-network-definition/%s"
    network_segment_trunk_path = "/vm-network-definition/%s/segments/%s"
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
    logical_networks_path = "/fabric-network"
    events_path = "/events"
    clusters_path = "/cluster"
    cluster_path = "/cluster/%s"
    cluster_service_instance_path = "/cluster/%s/service-instance/%s"

    def __init__(self, **kwargs):
        """Initialize a new client for the plugin."""
        self.format = 'json'
        self.action_prefix = '/api/hyper-v'
        self.hosts = self._get_vsm_hosts()
        netmask_to_str = lambda b: "%d.%d.%d.%d" % ((b & 0xff000000) >> 24,
                                                    (b & 0xff0000) >> 16,
                                                    (b & 0xff00) >> 8,
                                                    (b & 0xff))
        self.cidr_lookup_table = \
            dict([(i, netmask_to_str((2 ** 32) - (2 ** (32 - i))))
                  for i in xrange(33)])

    def list_port_profiles(self):
        """
        Fetch all policy profiles from the VSM.

        :returns: XML string
        """
        return self._get(self.port_profiles_path)

    def list_events(self, event_type=None, epoch=None):
        """
        Fetch all events of event_type from the VSM.

        :param event_type: type of event to be listed.
        :param epoch: timestamp after which the events occurred to be listed.
        :returns: XML string
        """
        if event_type:
            self.events_path = self.events_path + '?type=' + event_type
        return self._get(self.events_path)

    def create_bridge_domain(self, network):
        """
        Create a bridge domain on VSM.

        :param network: network dict
        """
        body = {'name': network['name'] + '_bd',
                'segmentId': network[providernet.SEGMENTATION_ID],
                'groupIp': network[n1kv_profile.MULTICAST_IP], }
        return self._post(self.bridge_domains_path,
                          body=body)

    def delete_bridge_domain(self, name):
        """
        Delete a bridge domain on VSM

        :param name: name of the bridge domain to be deleted
        """
        return self._delete(self.bridge_domain_path % (name))

    def create_network_segment(self, network, network_profile):
        """
        Create a network segment on the VSM

        :param network: network dict
        :param network_profile: network profile dict
        """
        LOG.debug(_("seg id %s\n"), network_profile['name'])
        body = {'name': network['name'],
                'id': network['id'],
                'networkDefinition': network_profile['name'], }
        if network[providernet.NETWORK_TYPE] == cisco_constants.TYPE_VLAN:
            body.update({'vlan': network[providernet.SEGMENTATION_ID]})
        if network[providernet.NETWORK_TYPE] == cisco_constants.TYPE_VXLAN:
            body.update({'bridgeDomain': network['name'] + '_bd'})
        return self._post(self.network_segments_path,
                          body=body)

    def update_network_segment(self, network_segment_name, body):
        """
        Update a network segment on the VSM

        Network segment on VSM can be updated to associate it with an ip-pool
        or update its description and segment id.

        :param network_segment_name: name of the network segment
        :param body: dict of arguments to be updated
        """
        return self._post(self.network_segment_path % (network_segment_name),
                          body=body)

    def delete_network_segment(self, network_segment_name):
        """
        Delete a network segment on the VSM

        :param network_segment_name: name of the network segment
        """
        return self._delete(self.network_segment_path % (network_segment_name))

    def create_logical_network(self, network_profile):
        """
        Create a logical network on the VSM

        :param network_profile: network profile dict
        """
        LOG.debug(_("logical network"))
        body = {'name': network_profile['name']}
        return self._post(self.logical_networks_path,
                          body=body)

    def create_network_segment_pool(self, network_profile):
        """
        Create a network segment pool on the VSM

        :param network_profile: network profile dict
        """
        LOG.debug(_("network_segment_pool"))
        body = {'name': network_profile['name'],
                'id': network_profile['id'],
                'fabricNetworkName': 'test'}
        return self._post(self.network_segment_pools_path,
                          body=body)

    def delete_network_segment_pool(self, network_segment_pool_name):
        """
        Delete a network segment pool on the VSM

        :param network_segment_pool_name: name of the network segment pool
        """
        return self._delete(self.network_segment_pool_path %
                            (network_segment_pool_name))

    def create_ip_pool(self, subnet):
        """
        Create an ip-pool on the VSM

        :param subnet: subnet dict
        """
        if subnet['cidr']:
            mask_len = subnet['cidr'].split('/')[1]
            netmask = self.cidr_lookup_table.get(int(mask_len), "")
        else:
            netmask = ""

        if subnet['allocation_pools']:
            address_range_start = subnet['allocation_pools'][0]['start']
            address_range_end = subnet['allocation_pools'][0]['end']
        else:
            address_range_start = None
            address_range_end = None

        body = {'dhcp': subnet['enable_dhcp'],
                'addressRangeStart': address_range_start,
                'addressRangeEnd': address_range_end,
                'ipAddressSubnet': netmask,
                'name': subnet['name'],
                'gateway': subnet['gateway_ip'], }
        return self._post(self.ip_pools_path,
                          body=body)

    def delete_ip_pool(self, subnet_name):
        """
        Delete an ip-pool on the VSM

        :param subnet_name: name of the subnet
        """
        return self._delete(self.ip_pool_path % (subnet_name))

    # TODO(abhraut): Removing tenantId from the request as a temp fix to allow
    #                port create. VSM CLI needs to be fixed. Should not
    #                interfere since VSM is not using tenantId as of now.
    def create_vm_network(self, port, vm_network_name, policy_profile):
        """
        Create a VM network on the VSM

        :param port: port dict
        :param vm_network_name: name of the VM network
        :param policy_profile: policy profile dict
        """
        body = {'name': vm_network_name,
                #'tenantId': port['tenant_id'],
                'vmNetworkDefinition': port['network_id'],
                'portProfile': policy_profile['name'],
                'portProfileId': policy_profile['id'],
                }
        return self._post(self.vm_networks_path,
                          body=body)

    def delete_vm_network(self, vm_network_name):
        """
        Delete a VM network on the VSM

        :param vm_network_name: name of the VM network
        """
        return self._delete(self.vm_network_path % (vm_network_name))

    def create_n1kv_port(self, port, vm_network_name):
        """
        Create a port on the VSM

        :param port: port dict
        :param vm_network_name: name of the VM network which imports this port
        """
        body = {'id': port['id'],
                'macAddress': port['mac_address']}
        return self._post(self.ports_path % (vm_network_name),
                          body=body)

    def update_n1kv_port(self, vm_network_name, port_id, body):
        """
        Update a port on the VSM

        Update the mac address associated with the port

        :param vm_network_name: name of the VM network which imports this port
        :param port_id: UUID of the port
        :param body: dict of the arguments to be updated
        """
        return self._post(self.port_path % ((vm_network_name), (port_id)),
                          body=body)

    def delete_n1kv_port(self, vm_network_name, port_id):
        """
        Delete a port on the VSM

        :param vm_network_name: name of the VM network which imports this port
        :param port_id: UUID of the port
        """
        return self._delete(self.port_path % ((vm_network_name), (port_id)))

    def get_vxlan_gw_clusters(self):
        """
        Fetches a list of all vxlan gateway clusters
        """
        return self._get(self.clusters_path)

    def add_trunk_segment(self, context, network_segment, trunk_dict):
        """
        Adds a segment to a trunk network segment on the VSM

        :param network_segment: Name of the trunk network segment
        :param trunk_dict: Dictionary containing the segment information (uuid
                            and link local vlan, if applicable) to be added to
                            the trunk network
        """
        body = {'segment': trunk_dict['segment'],
                'dot1q': trunk_dict['dot1qtag'],
                }
        return self._post(self.network_segment_path
                          % (network_segment), body=body)

    def del_trunk_segment(self, context, network_segment, segment):
        """
        Deletes a segment from a trunk network segment on the VSM

        :param network_segment: Name of the trunk network segment
        :param segment: Segment to be removed from the trunk
        """
        return self._delete(self.network_segment_trunk_path
                            % ((network_segment), (segment)))

    def add_multi_segment(self, context, cluster_id, encapsulation):
        """
        Adds a segment to a trunk network on the VSM

        :param cluster_id: The cluster id of the VXLAN gateway service module
        :param encapsulation: The encapsulation dictionary
                                containing the mapping
        """
        body = {'name': cluster_id,
                'serviceInstanceId': encapsulation['serviceInstance'],
                'segment1': encapsulation['segment1'],
                'segment2': encapsulation['segment2'],
                }
        return self._post(self.cluster_path % (cluster_id), body=body)

    def del_multi_segment(self, context, cluster_id, service_instance):
        """
        Deletes a multi-segment network pair on the VSM

        :param cluster_id: The cluster id of the VXLAN gateway service module
        :param service_instance: The service instance which
                                contains the encapsulation mapping
        """
        return self._delete(self.cluster_service_instance_path
                            % ((cluster_id), (service_instance)))

    def _handle_fault_response(self, status_code, replybody):
        """
        VSM responds with a INTERNAL SERVER ERRROR code (500) when VSM fails
        to fulfill the HTTP request.
        """
        if status_code == httplib.INTERNAL_SERVER_ERROR:
            raise c_exc.VSMError(reason=replybody)
        elif status_code == httplib.SERVICE_UNAVAILABLE:
            raise c_exc.VSMConnectionFailed

    def _do_request(self, method, action, body=None,
                    headers=None):
        """
        Perform the HTTP request

        The response is in either XML format or plain text. A GET method will
        invoke a XML response while a PUT/POST/DELETE returns message from the
        VSM in plain text format.
        Exception is raised when VSM replies with an INTERNAL SERVER ERROR HTTP
        status code (500) i.e. an error has occurred on the VSM or SERVICE
        UNAVAILABLE (503) i.e. VSM is not reachable.

        :param method: type of the HTTP request. POST, GET, PUT or DELETE
        :param action: path to which the client makes request
        :param body: dict for arguments which are sent as part of the request
        :param headers: header for the HTTP request
        :returns: XML or plain text in HTTP response
        """
        action = self.action_prefix + action
        if not headers and self.hosts:
            headers = self._get_auth_header(self.hosts[0])
        headers.update({'Content-Type': self._set_content_type('json')})
        if body:
            body = "%s  " % self._serialize(body)
            LOG.debug(_("req: %s"), body)
        conn = httplib.HTTPConnection(self.hosts[0])
        conn.request(method, action, body, headers)
        resp = conn.getresponse()
        _content_type = resp.getheader('content-type')
        replybody = resp.read()
        status_code = self._get_status_code(resp)
        LOG.debug(_("status_code %s\n"), status_code)
        if status_code == httplib.OK:
            if 'application/xml' in _content_type:
                return self._deserialize(replybody, status_code)
            elif 'text/plain' in _content_type:
                LOG.debug(_("VSM: %s"), replybody)
        elif status_code == httplib.INTERNAL_SERVER_ERROR:
            raise c_exc.VSMError(reason=replybody)
        elif status_code == httplib.SERVICE_UNAVAILABLE:
            raise c_exc.VSMConnectionFailed

    def _get_status_code(self, response):
        """
        Return status code from the HTTP response.

        :param response: HTTP response string
        :returns: HTTP status code in integer format
        """
        if hasattr(response, 'status_int'):
            return response.status_int
        else:
            return response.status

    def _serialize(self, data):
        """
        Serialize a dictionary with a single key into either xml or json

        :param data: data in the form of dict
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
        Deserialize an XML string into a dictionary

        :param data: XML string from the HTTP response
        :param status_code: integer status code from the HTTP response
        :return: data in the form of dict
        """
        if status_code == 204:
            return data
        return Serializer(self._serialization_metadata).deserialize(
            data, self._set_content_type('xml'))

    def _set_content_type(self, format=None):
        """
        Set the mime-type to either 'xml' or 'json'.

        :param format: format to be set.
        :return: mime-type string
        """
        if not format:
            format = self.format
        return "application/%s" % (format)

    def _delete(self, action, body=None, headers=None):
        return self._do_request("DELETE", action, body=body,
                                headers=headers)

    def _get(self, action, body=None, headers=None):
        return self._do_request("GET", action, body=body,
                                headers=headers)

    def _post(self, action, body=None, headers=None):
        return self._do_request("POST", action, body=body,
                                headers=headers)

    def _put(self, action, body=None, headers=None):
        return self._do_request("PUT", action, body=body,
                                headers=headers)

    def _get_vsm_hosts(self):
        """
        Retreive a list of VSM ip addresses.

        :return: list of host ip addresses.
        """
        host_list = []
        credentials = network_db_v2.get_all_n1kv_credentials()
        for cr in credentials:
            host_list.append(cr[cisco_constants.CREDENTIAL_NAME])
        return host_list

    def _get_auth_header(self, host_ip):
        """
        Retreive header with auth info for the VSM

        :param host_ip: IP address of the VSM
        :return: authorization header dict
        """
        username = c_cred.Store.get_username(host_ip)
        password = c_cred.Store.get_password(host_ip)
        auth = base64.encodestring("%s:%s" % (username, password))
        header = {"Authorization": "Basic %s" % auth}
        return header
