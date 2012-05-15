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

import json
import logging

from quantum.api import faults
from quantum import api_common
from quantum import wsgi
from quantum.api.v2 import views

LOG = logging.getLogger(__name__)


XML_NS_V20 = 'http://openstack.org/quantum/api/v2.0'


def create_resource(plugin, conf):
    # NOTE(cerberus): total punt on using the 1.0 and 1.1 API common
    # stuff because I want a clean decoupling. If it makes sense later
    # in the patch, let's reintroduce them as a v2 construct
    controller = ControllerV20(plugin),
    metadata = ControllerV20._serialization_metadata
    xmlns = common.XML_NS_V20

    # TODO(cerberus) There has to be a way to abstract this BS
    xml_serializer = wsgi.XMLDictSerializer(metadata, xmlns)
    xml_deserializer = wsgi.XMLDeserializer(metadata)


    body_serializers = {
        'application/xml': xml_serializer,
        'application/json': lambda x: json.dumps(x)
    }

    body_deserializers = {
        'application/xml': xml_deserializer,
        'application/json': lambda x: json.loads(x)
    }

    serializer = wsgi.ResponseSerializer(body_serializers,
                                         api_common.HeaderSerializer11())
    deserializer = wsgi.RequestDeserializer(body_deserializers)

    # TODO(cerberus): fix the faults crap later
    return wsgi.Resource(controller,
                         fault_body_function_v11,
                         deserializer,
                         serializer)


class ControllerV20(quantum.api.ports.Controller):
    _serialization_metadata = {
        "attributes": {
            "port": ["id", "network_id", "mac", "device_id", "tenant_id"]
        },
        "plurals": {
            "ports": "port",
        },
    }

    def _items(self, request):
        filter_opts = {}
        filter_opts.update(request.GET)
        port_list = self._plugin.get_all_ports(filter_opts=filter_opts)
        return dict(ports=[views.port(port) for port in port_list])

    def _item(self, request, id):
        port = self._plugin.get_port_details(id)
        return views.port(port)

    def index(self, req):
        context = req.environ['quantum.context']
        self._plugin.get_port_details(tenant_id=context.tenant_id,
                                      network_id=network_id,

    def show(self, request, id):
        context = req.environ['quantum.context']
        return self._item(request, id)

    def create(self, request, body):
        port_data = api_common._req

    def update(self, request, id, body):
        pass

    def delete(self, request, id):
        pass
