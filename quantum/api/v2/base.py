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
import json

from quantum.api import api_common
from quantum.api import faults
from quantum.common import utils
from quantum.api.v2 import views
from quantum import wsgi

LOG = logging.getLogger(__name__)
XML_NS_V20 = 'http://openstack.org/quantum/api/v2.0'


def show(request):
    """
    Extracts the list of fields to return
    """
    return [v for v in request.GET.getall('show') if v]


def filters(request):
    """
    Extracts the filters from the request string

    Returns a dict of lists for the filters:

    check=a&check=b&name=Bob&verbose=True&verbose=other

    becomes

    {'check': [u'a', u'b'], 'name': [u'Bob']}
    """
    return dict([(k, request.GET.getall(k))
                 for k in set(request.GET)
                 if k not in ('verbose', 'show') and
                    [v for v in request.GET.getall(k) if v]])


def verbose(request):
    """
    Determines the verbose fields for a request

    Returns a list of items that are requested to be verbose:

    check=a&check=b&name=Bob&verbose=True&verbose=other

    returns

    [True]

    and

    check=a&check=b&name=Bob&verbose=other

    returns

    ['other']

    """
    verbose = [utils.boolize(v) for v in request.GET.getall('verbose') if v]

    # NOTE(jkoelker) verbose=<bool> trumps all other verbose settings
    if True in verbose:
        return [True]
    elif False in verbose:
        return []

    return verbose


def create_resource(collection, resource, plugin, conf):
    # NOTE(cerberus): total punt on using the 1.0 and 1.1 API common
    # stuff because I want a clean decoupling. If it makes sense later
    # in the patch, let's reintroduce them as a v2 construct
    controller = Controller(plugin, collection, resource)

    # NOTE(jkoelker) punt on XML for now until we can genericizle it
    # NOTE(jkoelker) genericizle is a word
    # NOTE(jkoelker) just ask snoop dawg
    # NOTE(cerberus) pretty sure it's genericizzle. Two Zs.
    #metadata = Controller._serialization_metadata
    #xmlns = XML_NS_V20

    # TODO(cerberus) There has to be a way to abstract this BS
    #xml_serializer = wsgi.XMLDictSerializer(metadata, xmlns)
    #xml_deserializer = wsgi.XMLDeserializer(metadata)

    body_serializers = {
    #    'application/xml': xml_serializer,
        'application/json': lambda x: json.dumps(x)
    }

    body_deserializers = {
    #    'application/xml': xml_deserializer,
        'application/json': lambda x: json.loads(x)
    }

    serializer = wsgi.ResponseSerializer(body_serializers,
                                         api_common.HeaderSerializer11())
    deserializer = wsgi.RequestDeserializer(body_deserializers)

    # TODO(cerberus): fix the faults crap later
    return wsgi.Resource(controller,
                         faults.fault_body_function_v11,
                         deserializer,
                         serializer)


# TODO(anyone): super generic first cut
class Controller(api_common.QuantumController):
    def __init__(self, plugin, collection, resource):
        super(Controller, self).__init__(plugin)
        self._plugin = plugin
        self._collection = collection
        self._resource = resource
        self._view = getattr(views, self._resource)

    def _items(self, request):
        kwargs = dict(filters=filters(request),
                      verbose=verbose(request),
                      show=show(request))

        obj_getter = getattr(self._plugin,
                             "get_all_%s" % self._collection)
        obj_list = obj_getter(**kwargs)

        return {self._collection: [self._view(obj) for obj in obj_list]}

    def _item(self, request, id):
        kwargs = dict(verbose=verbose(request),
                      show=show(request))
        obj_getter = getattr(self._plugin,
                             "get_%s_details" % self._resource)
        obj = obj_getter(id, **kwargs)
        return {self._resource: self._view(obj)}

    def index(self, request):
        return self._items(request)

    def show(self, request, id):
        return self._item(request, id)

    def create(self, request, body):
        body = self._prepare_request_body(body)
        obj_creator = getattr(self._plugin,
                              "create_%s" % self._resource)
        obj = obj_creator(body)
        return {self._resource: self._view(obj)}

    def delete(self, request, id):
        obj_deleter = getattr(self._plugin,
                              "delete_%s" % self._resource)
        obj_deleter(id)

    def update(self, request, id, body):
        body = self._prepare_request_body(body)
        obj_updater = getattr(self._plugin,
                              "update_%s" % self._resource)
        obj = obj_updater(body)
        return {self._resource: self._view(obj)}
