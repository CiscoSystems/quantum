# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 New Dream Network, LLC (DreamHost)
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
# @author: Mark McClain, DreamHost

import weakref

from oslo.config import cfg

from quantum.agent.common import config
from quantum import context
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.openstack.common import periodic_task
from quantum.services.loadbalancer.drivers.haproxy import (
    agent_api,
    plugin_driver
)

LOG = logging.getLogger(__name__)
NS_PREFIX = 'qlbaas-'

OPTS = [
    cfg.StrOpt(
        'device_driver',
        default=('quantum.services.loadbalancer.drivers'
                 '.haproxy.namespace_driver.HaproxyNSDriver'),
        help=_('The driver used to manage the loadbalancing device'),
    ),
    cfg.StrOpt(
        'loadbalancer_state_path',
        default='$state_path/lbaas',
        help=_('Location to store config and state files'),
    ),
    cfg.StrOpt(
        'interface_driver',
        help=_('The driver used to manage the virtual interface')
    ),
    cfg.StrOpt(
        'user_group',
        default='nogroup',
        help=_('The user group'),
    ),
]


class LogicalDeviceCache(object):
    """Manage a cache of known devices."""

    class Device(object):
        """Inner classes used to hold values for weakref lookups."""
        def __init__(self, port_id, pool_id):
            self.port_id = port_id
            self.pool_id = pool_id

        def __eq__(self, other):
            return self.__dict__ == other.__dict__

        def __hash__(self):
            return hash((self.port_id, self.pool_id))

    def __init__(self):
        self.devices = set()
        self.port_lookup = weakref.WeakValueDictionary()
        self.pool_lookup = weakref.WeakValueDictionary()

    def put(self, device):
        port_id = device['vip']['port_id']
        pool_id = device['pool']['id']
        d = self.Device(device['vip']['port_id'], device['pool']['id'])
        if d not in self.devices:
            self.devices.add(d)
            self.port_lookup[port_id] = d
            self.pool_lookup[pool_id] = d

    def remove(self, device):
        if not isinstance(device, self.Device):
            device = self.Device(
                device['vip']['port_id'], device['pool']['id']
            )
        if device in self.devices:
            self.devices.remove(device)

    def remove_by_pool_id(self, pool_id):
        d = self.pool_lookup.get(pool_id)
        if d:
            self.devices.remove(d)

    def get_by_pool_id(self, pool_id):
        return self.pool_lookup.get(pool_id)

    def get_by_port_id(self, port_id):
        return self.port_lookup.get(port_id)

    def get_pool_ids(self):
        return self.pool_lookup.keys()


class LbaasAgentManager(periodic_task.PeriodicTasks):
    def __init__(self, conf):
        self.conf = conf
        try:
            vif_driver = importutils.import_object(conf.interface_driver, conf)
        except ImportError:
            # the driver is optional
            msg = _('Error importing interface driver: %s')
            raise SystemExit(msg % conf.interface_driver)
            vif_driver = None

        try:
            self.driver = importutils.import_object(
                conf.device_driver,
                config.get_root_helper(self.conf),
                conf.loadbalancer_state_path,
                vif_driver,
                self._vip_plug_callback
            )
        except ImportError:
            msg = _('Error importing loadbalancer device driver: %s')
            raise SystemExit(msg % conf.device_driver)
        ctx = context.get_admin_context_without_session()
        self.plugin_rpc = agent_api.LbaasAgentApi(
            plugin_driver.TOPIC_PROCESS_ON_HOST,
            ctx,
            conf.host
        )
        self.needs_resync = False
        self.cache = LogicalDeviceCache()

    def initialize_service_hook(self, started_by):
        self.sync_state()

    @periodic_task.periodic_task
    def periodic_resync(self, context):
        if self.needs_resync:
            self.needs_resync = False
            self.sync_state()

    @periodic_task.periodic_task(spacing=6)
    def collect_stats(self, context):
        for pool_id in self.cache.get_pool_ids():
            try:
                stats = self.driver.get_stats(pool_id)
                if stats:
                    self.plugin_rpc.update_pool_stats(pool_id, stats)
            except Exception:
                LOG.exception(_('Error upating stats'))
                self.needs_resync = True

    def _vip_plug_callback(self, action, port):
        if action == 'plug':
            self.plugin_rpc.plug_vip_port(port['id'])
        elif action == 'unplug':
            self.plugin_rpc.unplug_vip_port(port['id'])

    def sync_state(self):
        known_devices = set(self.cache.get_pool_ids())
        try:
            ready_logical_devices = set(self.plugin_rpc.get_ready_devices())

            for deleted_id in known_devices - ready_logical_devices:
                self.destroy_device(deleted_id)

            for pool_id in ready_logical_devices:
                self.refresh_device(pool_id)

        except Exception:
            LOG.exception(_('Unable to retrieve ready devices'))
            self.needs_resync = True

        self.remove_orphans()

    def refresh_device(self, pool_id):
        try:
            logical_config = self.plugin_rpc.get_logical_device(pool_id)

            if self.driver.exists(pool_id):
                self.driver.update(logical_config)
            else:
                self.driver.create(logical_config)
            self.cache.put(logical_config)
        except Exception:
            LOG.exception(_('Unable to refresh device for pool: %s'), pool_id)
            self.needs_resync = True

    def destroy_device(self, pool_id):
        device = self.cache.get_by_pool_id(pool_id)
        if not device:
            return
        try:
            self.driver.destroy(pool_id)
            self.plugin_rpc.pool_destroyed(pool_id)
        except Exception:
            LOG.exception(_('Unable to destroy device for pool: %s'), pool_id)
            self.needs_resync = True
        self.cache.remove(device)

    def remove_orphans(self):
        try:
            self.driver.remove_orphans(self.cache.get_pool_ids())
        except NotImplementedError:
            pass  # Not all drivers will support this

    def reload_pool(self, context, pool_id=None, host=None):
        """Handle RPC cast from plugin to reload a pool."""
        if pool_id:
            self.refresh_device(pool_id)

    def modify_pool(self, context, pool_id=None, host=None):
        """Handle RPC cast from plugin to modify a pool if known to agent."""
        if self.cache.get_by_pool_id(pool_id):
            self.refresh_device(pool_id)

    def destroy_pool(self, context, pool_id=None, host=None):
        """Handle RPC cast from plugin to destroy a pool if known to agent."""
        if self.cache.get_by_pool_id(pool_id):
            self.destroy_device(pool_id)
