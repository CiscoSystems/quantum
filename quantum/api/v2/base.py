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

import webob.exc

from quantum.common import exceptions
from quantum.common import utils
from quantum.api.v2 import views
from quantum import wsgi2

LOG = logging.getLogger(__name__)
XML_NS_V20 = 'http://openstack.org/quantum/api/v2.0'

FAULT_MAP = {exceptions.NetworkNotFound: webob.exc.HTTPNotFound,
             exceptions.NetworkInUse: webob.exc.HTTPConflict,
             exceptions.PortNotFound: webob.exc.HTTPNotFound,
             exceptions.StateInvalid: webob.exc.HTTPBadRequest,
             exceptions.PortInUse: webob.exc.HTTPConflict}


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
    return dict(((k, request.GET.getall(k))
                 for k in set(request.GET)
                 if k not in ('verbose', 'show') and
                    (v for v in request.GET.getall(k) if v)))


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


def create_resource(collection, resource, plugin, conf, params):
    # NOTE(cerberus): total punt on using the 1.0 and 1.1 API common
    # stuff because I want a clean decoupling. If it makes sense later
    # in the patch, let's reintroduce them as a v2 construct
    controller = Controller(plugin, collection, resource, params)

    # NOTE(jkoelker) punt on XML for now until we can genericizle it
    # NOTE(jkoelker) genericizle is a word
    # NOTE(jkoelker) just ask snoop dawg
    # NOTE(cerberus) pretty sure it's genericizzle. Two Zs.
    #metadata = Controller._serialization_metadata
    #xmlns = XML_NS_V20

    # TODO(cerberus) There has to be a way to abstract this BS
    #xml_serializer = wsgi.XMLDictSerializer(metadata, xmlns)
    #xml_deserializer = wsgi.XMLDeserializer(metadata)

    serializers = {
    #    'application/xml': xml_serializer,
    }

    deserializers = {
    #    'application/xml': xml_deserializer,
    }

    return wsgi2.Resource(controller, FAULT_MAP, deserializers, serializers)


class Controller(object):
    def __init__(self, plugin, collection, resource, params):
        self._plugin = plugin
        self._collection = collection
        self._resource = resource
        self._params = params
        self._view = getattr(views, self._resource)

    def _items(self, request):
        """Retrieves and formats a list of elements of the requested entity"""
        kwargs = {'filters': filters(request),
                  'verbose': verbose(request),
                  'show': show(request)}

        obj_getter = getattr(self._plugin, "get_%s" % self._collection)
        obj_list = obj_getter(request.context, **kwargs)
        return {self._collection: [{self._resource: self._view(obj)}
                                            for obj in obj_list]}

    def _item(self, request, id):
        """Retrieves and formats a single element of the requested entity"""
        kwargs = {'verbose': verbose(request),
                  'show': show(request)}
        obj_getter = getattr(self._plugin,
                             "get_%s" % self._resource)
        obj = obj_getter(request.context, id, **kwargs)
        return {self._resource: self._view(obj)}

    def index(self, request):
        """Returns a list of the requested entity"""
        return self._items(request)

    def show(self, request, id):
        """Returns detailed information about the requested entity"""
        return self._item(request, id)

    def create(self, request, body=None):
        """Creates a new instance of the requested entity"""
        body = self._prepare_request_body(body, allow_bulk=True)
        obj_creator = getattr(self._plugin,
                              "create_%s" % self._resource)
        kwargs = {self._resource: body}
        obj = obj_creator(request.context, **kwargs)
        return {self._resource: self._view(obj)}

    def delete(self, request, id):
        """Deletes the specified entity"""
        obj_deleter = getattr(self._plugin,
                              "delete_%s" % self._resource)
        obj_deleter(request.context, id)

    def update(self, request, id, body=None):
        """Updates the specified entity's attributes"""
        body = self._prepare_request_body(body)
        obj_updater = getattr(self._plugin,
                              "update_%s" % self._resource)
        kwargs = {self._resource: body}
        obj = obj_updater(request.context, id, **kwargs)
        return {self._resource: self._view(obj)}

    def _prepare_request_body(self, body, allow_bulk=False):
        """ verifies required parameters are in request body.
            Parameters with default values are considered to be
            optional.

            body argument must be the deserialized body
        """
        if not body:
            raise webob.exc.HTTPBadRequest(_("Resource body required"))

        body = body or {self._resource: {}}

        if self._collection in body and allow_bulk:
            bulk_body = [self._prepare_request_body({self._resource: b})
                         if self._resource not in b
                         else self._prepare_request_body(b)
                         for b in body[self._collection]]
            return {self._collection: bulk_body}

        elif self._collection in body and not allow_bulk:
            raise webob.exc.HTTPBadRequest("Bulk operation not supported")

        res_dict = body.get(self._resource)
        if res_dict is None:
            msg = _("Unable to find '%s' in request body") % self._resource
            raise webob.exc.HTTPBadRequest(msg)

        for param in self._params:
            param_value = res_dict.get(param['attr'], param.get('default'))
            if param_value is None:
                msg = _("Failed to parse request. Parameter: %s not "
                        "specified") % param
                raise webob.exc.HTTPUnprocessableEntity(msg)
            res_dict[param['attr']] = param_value
        return body
