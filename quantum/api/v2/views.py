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


LOG = logging.getLogger(__name__)

# NOTE(cerberus): see http://pyvideo.org/video/880/stop-writing-classes for
# justification of everything below

def tagger(data):
    if 'tags' not in data:
        return []
    return data['tags']


def port(port_data):
    res = dict(tags=tagger(port_data),
               network_id=port_data['network_id'],
               mac=port_data['mac'],
               device_id=port_data['device_id'],
               tenant_id=port_data['tenant_id'])
    return dict(port=res)


def network(network_data):
    res = dict(tags=tagger(network_data))
    return res


def subnet(subnet_data):
    res = dict(tags=tagger(subnet_data))
    return res


def ip(ip_data):
    res = dict(tags=tagger(ip_data))
    return res


def route(route_data):
    res = dict(tags=tagger(route_data))
    return res


def floating_ip(floating_ip_data):
    res = dict(tags=tagger(floating_ip_data))
    return res
