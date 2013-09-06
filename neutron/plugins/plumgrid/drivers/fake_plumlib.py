# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 PLUMgrid, Inc. All Rights Reserved.
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
# @author: Edgar Magana, emagana@plumgrid.com, PLUMgrid, Inc.


from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class Plumlib():
    """
    Class PLUMgrid Fake Library. This library is a by-pass implementation
    for the PLUMgrid Library. This class is being used by the unit test
    integration in Neutron.
    """

    def __init__(self):
        LOG.info('Python PLUMgrid Fake Library Started ')
        pass

    def director_conn(self, director_plumgrid, director_port, timeout,
                      director_admin, director_password):
        LOG.info('Fake Director: %s', director_plumgrid + ':' + director_port)
        pass

    def create_network(self, tenant_id, net_db):
        pass

    def update_network(self, tenant_id, net_id):
        pass

    def delete_network(self, net_db, net_id):
        pass

    def create_subnet(self, sub_db, net_db, ipnet):
        pass

    def update_subnet(self, org_sub_db, new_sub_db, ipnet):
        pass

    def delete_subnet(self, tenant_id, net_db, net_id):
        pass

    def create_port(self, port_db, router_db):
        pass

    def update_port(self, port_db, router_db):
        pass

    def delete_port(self, port_db, router_db):
        pass

    def create_router(self, tenant_id, router_db):
        pass

    def update_router(self, router_db, router_id):
        pass

    def delete_router(self, tenant_id, router_id):
        pass

    def add_router_interface(self, tenant_id, router_id, port_db, ipnet):
        pass

    def remove_router_interface(self, tenant_id, net_id, router_id):
        pass

    def create_floatingip(self, net_db, floating_ip):
        pass

    def update_floatingip(self, net_db, floating_ip, id):
        pass

    def delete_floatingip(self, net_db, floating_ip_org, id):
        pass
