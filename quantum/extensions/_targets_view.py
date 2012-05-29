# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Cisco Systems, Inc.
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
#
#    @author Sumit Naiksatam
#

from quantum.api.api_common import OperationalStatus


def get_view_builder(req, version):
    base_url = req.application_url
    view_builder = {
        '1.1': ViewBuilder11
    }[version](base_url)
    return view_builder


class ViewBuilder11(object):

    def __init__(self, base_url=None):
        """
        :param base_url: url of the root wsgi application
        """
        self.base_url = base_url

    def build(self, target_data):
        """Return a detailed model of a target"""
        return dict(target=dict(tag=target_data['target'],
                                description=target_data['description']
                               ))
