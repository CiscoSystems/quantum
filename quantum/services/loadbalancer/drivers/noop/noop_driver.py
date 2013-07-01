# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Radware LTD.
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
# @author: Avishay Balderman, Radware


from quantum.openstack.common import log as logging
from quantum.services.loadbalancer.drivers import (
    abstract_driver
)

LOG = logging.getLogger(__name__)


def log(method):
    def wrapper(*args, **kwargs):
        data = {"method_name": method.__name__, "args": args, "kwargs": kwargs}
        LOG.debug(_('NoopLbaaSDriver method %(method_name)s'
                    'called with arguments %(args)s %(kwargs)s ')
                  % data)
        return method(*args, **kwargs)
    return wrapper


class NoopLbaaSDriver(abstract_driver.LoadBalancerAbstractDriver):

    """A dummy lbass driver that:
       1) Logs methods input
       2) Uses the plugin API in order to update
          the config elements status in DB
    """

    def __init__(self, plugin):
        self.plugin = plugin

    @log
    def create_vip(self, context, vip):
        pass

    @log
    def update_vip(self, context, old_vip, vip):
        pass

    @log
    def delete_vip(self, context, vip):
        self.plugin._delete_db_vip(context, vip["id"])

    @log
    def create_pool(self, context, pool):
        pass

    @log
    def update_pool(self, context, old_pool, pool):
        pass

    @log
    def delete_pool(self, context, pool):
        pass

    @log
    def stats(self, context, pool_id):
        return {"bytes_in": 0,
                "bytes_out": 0,
                "active_connections": 0,
                "total_connections": 0}

    @log
    def create_member(self, context, member):
        pass

    @log
    def update_member(self, context, old_member, member):
        pass

    @log
    def delete_member(self, context, member):
        self.plugin._delete_db_member(context, member["id"])

    @log
    def create_health_monitor(self, context, health_monitor):
        pass

    @log
    def update_health_monitor(self, context, old_health_monitor,
                              health_monitor,
                              pool_association):
        pass

    @log
    def create_pool_health_monitor(self, context,
                                   health_monitor, pool_id):
        pass

    @log
    def delete_pool_health_monitor(self, context, health_monitor, pool_id):
        self.plugin._delete_db_pool_health_monitor(
            context, health_monitor["id"],
            pool_id
        )
