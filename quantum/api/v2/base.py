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

from quantum.common import utils

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


class Controller(object):
    def __init__(self, plugin):
        super(Controller, self).__init__()
        self._plugin = plugin
