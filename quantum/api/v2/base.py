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

from quantum.api import api_common
from quantum.api.v2 import views


LOG = logging.getLogger(__name__)


XML_NS_V20 = 'http://openstack.org/quantum/api/v2.0'


def create_resource(collection, resource, plugin, conf):
    # NOTE(cerberus): total punt on using the 1.0 and 1.1 API common
    # stuff because I want a clean decoupling. If it makes sense later
    # in the patch, let's reintroduce them as a v2 construct
    controller = ControllerV20(plugin, collection, resource)
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

# TODO(anyone): super generic first cut
class Controller(api_commom.QuantumController):
    def __init__(self, plugin, collection, resource):
        super(Controller, self).__init__()
        self._plugin = plugin
        self._collection = collection
        self._resource = resource
        self._view = getattr(views, self._resource)

    def _items(self, request):
        filter_opts = {}
        filter_opts.update(request.GET)

        obj_getter = getattr(self._plugin, "get_all_%s" % self._collection)
        obj_list = obj_getter(filter_opts=filter_opts)

        return dict(ports=[self._view(obj) for obj in obj_list])

    def _item(self, request, id):
        obj_getter = getattr(self._plugin, "get_%s_details" % self._resource)
        obj = obj_getter(id)
        return self._view(obj)

    def index(self, req):
        return self._items(req)

    def show(self, req, id):
        return self._item(req, id)

    def create(self, req, body):
        body = self._prepare_request_body(body)
        obj_creator = getattr(self._plugin, "create_%s" % self._resource)
        obj_creator(body)
        return self._view(obj)

    def delete(self, req, id):
        obj_deleter = getattr(self._plugin, "delete_%s" % self._resource)
        obj_deleter(id)

    def update(self, req, id, body):
        body = self._prepare_request_body(body)
        obj_updater = getattr(self._plugin, "update_%s" % self._resource)
        obj_updater(body)
        return self._view(obj)
