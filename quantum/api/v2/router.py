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
from quantum.api import ips
from quantum.api import floatingips
from quantum.api import networks
from quantum.api import ports
from quantum.api import routes
from quantum.api import subnets


LOG = logging.getLogger(__name__)
HEX_ELEM = '[0-9A-Fa-f]'
UUID_PATTERN = '-'.join([HEX_ELEM + '{8}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{4}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{12}'])
COLLECTION_ACTIONS = ['index', 'create']
MEMBER_ACTIONS = ['show', 'update', 'delete']
UUID_REQUIREMENT = {'id': UUID_PATTERN}


class APIRouter(wsgi.Router):

    @classmethod
    def factory(cls, global_config, **local_config):
        return cls(global_config, **local_config)

    def __init__(self, conf, **local_config):
        mapper = routes_mapper.Mapper()
        plugin = manager.QuantumManager.get_plugin(conf)

        kwargs = dict(plugin=plugin, conf=conf)
        ips_resource = ips.create_resource(**kwargs)
        floatingips_resource = floatingips.create_resource(**kwargs)
        networks_resource = networks.create_resource(**kwargs)
        ports_resource = ports.create_resource(**kwargs)
        routes_resource = routes.create_resource(**kwargs)
        subnets_resource = subnets.create_resource(**kwargs)

        col_kwargs = dict(collection_actions=COLLECTION_ACTIONS,
                          member_actions=MEMBER_ACTIONS,
                          requirements=UUID_REQUIREMENT)

        with mapper.collection('networks', 'network',
                               controller=networks_resource,
                               **col_kwargs) as net_m:
            with net_m.collection('subnets', 'subnet',
                                  controller=subnets_resource,
                                  **col_kwargs) as subnet_m:
                subnet_m.collection('routes', 'route',
                                    controller=routes_resource,
                                    **col_kwargs)
        mapper.collection('ports', 'port', controller=ports_resource,
                          **col_kwargs)
        mapper.collection('ips', 'ip', controller=ips_resource,
                          **col_kwargs)
        mapper.collection('floatingips', 'floatingip',
                          controller=floatingips_resource,
                          **col_kwargs)

        super(APIRouter, self).__init__(mapper)
