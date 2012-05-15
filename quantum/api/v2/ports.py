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

from quantum.api import faults
from quantum import api_common
from quantum import wsgi

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
    json_serializer = wsgi.JSONDictSerializer()
    xml_deserializer = wsgi.XMLDeserializer(metadata)
    json_deserializer = wsgi.JSONDeserializer()

    body_serializers = {
        'application/xml': xml_serializer,
        'application/json': json_serializer,
    }

    body_deserializers = {
        'application/xml': xml_deserializer,
        'application/json': json_deserializer,
    }

    # TODO(cerberus) fix the header serializer crap
    serializer = wsgi.ResponseSerializer(body_serializers,
                                         api_common.HeaderSerializer11())
    deserializer = wsgi.RequestDeserializer(body_deserializers)

    # TODO(cerberus): fix the faults crap later
    return wsgi.Resource(controller,
                         fault_body_function_v11,
                         deserializer,
                         serializer)

class ControllerV20(common.QuantumController):
    def __init__(self, plugin):
        super(Controller, self).__init__(plugin)
