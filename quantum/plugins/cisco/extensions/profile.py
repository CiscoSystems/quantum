"""
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
# @author: Abhishek Raut, Cisco Systems, Inc
# @author: Rudrajit Tapadar, Cisco Systems, Inc
#
"""

from abc import abstractmethod

from oslo.config import cfg

from quantum import manager
from quantum import quota
from quantum.common import exceptions as qexception
from quantum.api.v2 import attributes as attr
from quantum.api.v2 import base
from quantum.api import extensions


# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'profiles': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:regex': attr.UUID_PATTERN},
               'is_visible': True},
        'profile_id': {'allow_post': False, 'allow_put': False,
                       'validate': {'type:regex': attr.UUID_PATTERN},
                       'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': ''},
        'profile_type': {'allow_post': True, 'allow_put': True,
                         'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'segment_type': {'allow_post': True, 'allow_put': True,
                         'is_visible': True, 'default': ''},
        'segment_range': {'allow_post': True, 'allow_put': True,
                          'is_visible': True, 'default': ''},
        'multicast_ip_range': {'allow_post': True, 'allow_put': True,
                               'is_visible': True, 'default': '0.0.0.0'},
        'multicast_ip_index': {'allow_post': False, 'allow_put': False,
                               'is_visible': False, 'default': '0'},
    },
}


class Profile(object):

    @classmethod
    def get_name(cls):
        return "Cisco N1kv Profiles"

    @classmethod
    def get_alias(cls):
        return "profile"

    @classmethod
    def get_description(cls):
        return ("Profile includes the type of profile for N1kv")

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/n1kv/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2012-07-20T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        exts = []
        resource_name = "profile"
        collection_name = resource_name + "s"
        plugin = manager.QuantumManager.get_plugin()
        params = RESOURCE_ATTRIBUTE_MAP.get(collection_name, dict())
        member_actions = {}
        controller = base.create_resource(collection_name,
                                          resource_name,
                                          plugin, params,
                                          member_actions=member_actions)
        return [extensions.ResourceExtension(collection_name,
                                             controller,
                                             member_actions=member_actions)]


class ProfileBase(object):

    @abstractmethod
    def create_profile(self, context, profile):
        pass

    @abstractmethod
    def get_profile(self, context, id, fields=None):
        pass

    @abstractmethod
    def update_profile(self, context, id, profile):
        pass

    @abstractmethod
    def delete_profile(self, context, id):
        pass
