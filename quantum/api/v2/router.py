# Copyright (c) 2012 OpenStack, LLC.
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

import logging

import routes as routes_mapper

from quantum import manager
from quantum import wsgi

from quantum.api import v2 as api


LOG = logging.getLogger(__name__)
HEX_ELEM = '[0-9A-Fa-f]'
UUID_PATTERN = '-'.join([HEX_ELEM + '{8}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{4}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{12}'])
COLLECTION_ACTIONS = ['index', 'create']
MEMBER_ACTIONS = ['show', 'update', 'delete']
REQUIREMENTS = {'id': UUID_PATTERN, 'format': 'xml|json'}


def _parent_path(parent, collection):
    return '/{%s_id}/%s' % (parent.resource_name, collection)


def _requirements(*parents):
    req = dict(**REQUIREMENTS)
    for parent in parents:
        req['%s_id' % parent.resource_name] = UUID_PATTERN
    return req


class APIRouterV2(wsgi.Router):

    @classmethod
    def factory(cls, global_config, **local_config):
        return cls(global_config, **local_config)

    def __init__(self, conf, **local_config):
        mapper = routes_mapper.Mapper()
        plugin = manager.QuantumManager.get_plugin(conf)

        kwargs = dict(plugin=plugin, conf=conf)

        col_kwargs = dict(collection_actions=COLLECTION_ACTIONS,
                          member_actions=MEMBER_ACTIONS)

        reqs = _requirements()

        def _map_resource(resources, resource, req=None, parent=None):
            module = getattr(api, resources)
            controller = module.create_resource(**kwargs)
            mapper_kwargs = dict(collection_name=resources,
                                resouce_name=resource,
                                controller=controller,
                                requiements=req or reqs,
                                **col_kwargs)
            if parent:
                kwargs['path_prefix'] = parent
            return mapper.collection(**mapper_kwargs)

        net_mapper = _map_resource('networks', 'network', REQUIREMENTS)
        subnet_mapper = _map_resource('subnets', 'subnet',
                                      _requirements(net_mapper),
                                      _parent_path(net_mapper, 'subnets'))
        _map_resource('routes', 'route',
                      _requirements(net_mapper, subnet_mapper),
                      _parent_path(subnet_mapper, 'routes'))

        _map_resource('ports', 'port')
        _map_resource('ips', 'ip')
        _map_resource('floatingips', 'floatingip')

        super(APIRouterV2, self).__init__(mapper)
