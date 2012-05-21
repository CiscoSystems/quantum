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


# NOTE(cerberus): see http://pyvideo.org/video/880/stop-writing-classes for
# justification of everything below
def tagger(data):
    return data.get('tags', list())


def filter_keys(data, keys):
    return dict((item for item in data.iteritems() if item[0] in keys))


def resource(data, keys):
    res = filter_keys(data, keys)
    res['tags'] = tagger(data)
    return res


def port(port_data):
    keys = ('id', 'network_id', 'mac', 'device_id', 'tenant_id')
    return resource(port_data, keys)


def network(network_data):
    keys = ('id', 'label', 'subnets', 'mac_ranges')
    return resource(network_data, keys)


def subnet(subnet_data):
    keys = ('id', 'network', 'tenant_id', 'excluded_ranges', 'version',
            'routes', 'enforce_unique', 'cidr')
    return resource(subnet_data, keys)


def ip(ip_data):
    keys = ('id', 'subnet', 'device_id', 'tenant_id', 'ports', 'version',
            'address')
    return resource(ip_data, keys)


def route(route_data):
    keys = ('id', 'cidr', 'version', 'gateway', 'target')
    return resource(route_data, keys)
