# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Utility methods for working with WSGI servers redux
"""
import json
import logging

import webob
import webob.exc
import webob.dec

from quantum import wsgi


LOG = logging.getLogger(__name__)


class Request(webob.Request):
    """Add some Openstack API-specific logic to the base webob.Request."""

    def best_match_content_type(self):
        supported = ('application/json', )
        return self.accept.best_match(supported,
                                      default_match='application/json')

    @property
    def context(self):
        #this is here due to some import loop issues.(mdragon)
        from quantum.context import get_admin_context
        #Eventually the Auth[NZ] code will supply this. (mdragon)
        #when that happens this if block should raise instead.
        if 'quantum.context' not in self.environ:
            self.environ['quantum.context'] = get_admin_context()
        return self.environ['quantum.context']


def Resource(controller, deserializers=None, serializers=None):
    """Represents an API entity resource and the associated serialization and
    deserialization logic
    """
    # NOTE(jkoelker) bit of a nameing collision here
    ds = {'application/xml': wsgi.XMLDeserializer(),
          'application/json': lambda x: json.loads(x)}
    s = {'application/xml': wsgi.XMLDictSerializer(),
        'application/json': lambda x: json.dumps(x)}
    format_types = {'xml': 'application/xml',
                    'json': 'application/json'}

    ds.update(deserializers or {})
    s.update(serializers or {})

    deserializers = ds
    serializers = s

    @webob.dec.wsgify(RequestClass=Request)
    def resource(request):
        route_args = request.environ.get('wsgiorg.routing_args')
        if route_args:
            args = route_args[1].copy()
        else:
            args = {}

        # NOTE(jkoelker) by now the controller is already found, remove
        #                it from the args if it is in the matchdict
        args.pop('controller', None)
        fmt = args.pop('format', None)
        action = args.pop('action', None)

        content_type = format_types.get(fmt,
                                        request.best_match_content_type())
        deserializer = deserializers.get(content_type)

        body = {}
        if request.body:
            body = deserializer(request.body)

        # NOTE(jkoelker) Prevent the body from overriding values in args
        body.update(args)
        args = body

        method = getattr(controller, action)

        result = method(request=request, **args)

        if isinstance(result, webob.exc.HTTPException):
            return result

        serializer = serializers.get(content_type)
        return  webob.Response(request=request,
                               content_type=content_type,
                               body=serializer(result))
    return resource
