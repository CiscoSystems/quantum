
from quantum.api.v2 import attributes as attr
from quantum.api.v2 import base
from quantum.api import extensions
from quantum import manager
RESOURCE_NAME = "network_profile"
COLLECTION_NAME = "%ss" % RESOURCE_NAME
EXT_ALIAS = RESOURCE_NAME


# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    COLLECTION_NAME: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:regex': attr.UUID_PATTERN},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': ''},
        'segment_type': {'allow_post': True, 'allow_put': True,
                         'is_visible': True, 'default': ''},
        'segment_range': {'allow_post': True, 'allow_put': True,
                          'is_visible': True, 'default': ''},
        'multicast_ip_range': {'allow_post': True, 'allow_put': True,
                               'is_visible': True, 'default': '0.0.0.0'},
        'multicast_ip_index': {'allow_post': False, 'allow_put': False,
                               'is_visible': False, 'default': '0'},
        'add_tenant': {'allow_post': True, 'allow_put': True,
                       'is_visible': True, 'default': None},
        'remove_tenant': {'allow_post': True, 'allow_put': True,
                          'is_visible': True, 'default': None},
        },
}


class Networkprofile(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Cisco N1kv Network Profiles"

    @classmethod
    def get_alias(cls):
        return EXT_ALIAS

    @classmethod
    def get_description(cls):
        return ("Profile includes the type of profile for N1kv")

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/n1kv/network-profile/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2012-07-20T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        controller = base.create_resource(
            COLLECTION_NAME,
            RESOURCE_NAME,
            manager.QuantumManager.get_plugin(),
            RESOURCE_ATTRIBUTE_MAP.get(COLLECTION_NAME))
        return [extensions.ResourceExtension(COLLECTION_NAME, controller)]
