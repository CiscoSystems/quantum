# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack Foundation.
# All rights reserved.
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
# @author: Bob Melander, Cisco Systems, Inc.

from quantum.api import extensions
from quantum.api.v2 import attributes
from quantum.common import exceptions as qexception


# Trunk port Exceptions
class VlanAlreadyUsedinTrunk(qexception.InUse):
    message = _("The VLAN %(vlan_tag)s is already in use.")

class NetworkInUse(qexception.InUse):
    message = _("Network %(network_id)s still has active ports")

class NotTrunkNetwork(qexception.InUse):
    message = _("Network %(network_id)s is not a trunk network")

TRUNKED_NETWORKS = 'trunkport:trunked_networks'

EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        TRUNKED_NETWORKS: {'allow_post': True, 'allow_put': True,
                           'validate': {'type:dict_or_nodata': None},
                           'default': None,
                           'is_visible': True},
    }
}


class Trunkport(extensions.ExtensionDescriptor):
    """Extension class to support trunk ports.

    This class is used by quantum's extension framework to support
    ports that trunk multiple networks. Such trunk ports belong
    to special networks used only for trunk ports. Such networks
    should have no subnets associated.
    No new resources are defined by this extension. Instead, the
    network resource's request and response messages are extended
    with an attribute 'trunked_networks' in the trunkport namespace.
    If the attribute is None, the network is not for trunk ports.
    Otherwise the attribute is a dict of the form:

    trunked_network = {
                'd22e42a2-4412-a32e-7e2e-56dcfbb243cc': 5,
                'bbe2365c-652e-2bef-62ea-b55ed23a33ac': 6,
                '6243eb53-fe6b-6ae2-cd31-b2c351fcb2de': 10 }

    that contains network_ids and the vlans used to trunk those networks.
    The dictionary can be specified in the 'Create' and 'Update' calls.
    The plugin will then trunk the specified networks according to the
    dict. If a specified vlan tag is None a value will be assigned to it.
    For provider networks the vlan tag in the 'Create' and 'Update' is
    always suppose to be None or the vlan used by the provider network.
    """

    @classmethod
    def get_name(cls):
        return "Trunk port"

    @classmethod
    def get_alias(cls):
        return "trunkport"

    @classmethod
    def get_description(cls):
        return "Allow ports to trunk multiple networks"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/trunkport/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2012-09-07T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
