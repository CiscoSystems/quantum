# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.  All rights reserved.
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
# @author: Sumit Naiksatam, Cisco Systems, Inc.
# @author: Rohit Agarwalla, Cisco Systems, Inc.

from copy import deepcopy
import inspect
import logging

from quantum.openstack.common import importutils
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.plugins.openvswitch import ovs_db_v2 as odb
from quantum import quantum_plugin_base_v2


LOG = logging.getLogger(__name__)


class NetworkMultiHostV2(quantum_plugin_base_v2.QuantumPluginBaseV2):
    """
    This implementation works with OVS and Nexus plugin for the
    following topology:
    One or more servers to a nexus switch.
    """
    _plugins = {}
    _inventory = {}

    def __init__(self):
        """
        Initialize the segmentation manager, check which device plugins are
        configured, and load the inventories those device plugins for which the
        inventory is configured
        """
        self._vlan_mgr = importutils.import_object(conf.MANAGER_CLASS)
        for key in conf.PLUGINS[const.PLUGINS].keys():
            plugin_obj = conf.PLUGINS[const.PLUGINS][key]
            self._plugins[key] = importutils.import_object(plugin_obj)
            LOG.debug("Loaded device plugin %s\n" %
                      conf.PLUGINS[const.PLUGINS][key])
            if key in conf.PLUGINS[const.INVENTORY].keys():
                inventory_obj = conf.PLUGINS[const.INVENTORY][key]
                self._inventory[key] = importutils.import_object(inventory_obj)
                LOG.debug("Loaded device inventory %s\n" %
                          conf.PLUGINS[const.INVENTORY][key])

        LOG.debug("%s.%s init done" % (__name__, self.__class__.__name__))

    def _func_name(self, offset=0):
        """Get the name of the calling function"""
        return inspect.stack()[1 + offset][3]

    def _invoke_plugin_per_device(self, plugin_key, function_name, args):
        """
        Invokes a device plugin's relevant functions (on the it's
        inventory and plugin implementation) for completing this operation.
        """
        if not plugin_key in self._plugins.keys():
            LOG.info("No %s Plugin loaded" % plugin_key)
            LOG.info("%s: %s with args %s ignored" %
                     (plugin_key, function_name, args))
            return
        device_params = self._invoke_inventory(plugin_key, function_name,
                                               args)
        device_ips = device_params[const.DEVICE_IP]
        if not device_ips:
            return [self._invoke_plugin(plugin_key, function_name, args,
                                        device_params)]
        else:
            output = []
            for device_ip in device_ips:
                new_device_params = deepcopy(device_params)
                new_device_params[const.DEVICE_IP] = device_ip
                output.append(self._invoke_plugin(plugin_key, function_name,
                                                  args, new_device_params))
            return output

    def _invoke_inventory(self, plugin_key, function_name, args):
        """
        Invokes the relevant function on a device plugin's
        inventory for completing this operation.
        """
        if not plugin_key in self._inventory.keys():
            LOG.info("No %s inventory loaded" % plugin_key)
            LOG.info("%s: %s with args %s ignored" %
                     (plugin_key, function_name, args))
            return {const.DEVICE_IP: []}
        else:
            return getattr(self._inventory[plugin_key], function_name)(args)

    def _invoke_plugin(self, plugin_key, function_name, args, kwargs):
        """
        Invokes the relevant function on a device plugin's
        implementation for completing this operation.
        """
        func = getattr(self._plugins[plugin_key], function_name)
        func_args_len = int(inspect.getargspec(func).args.__len__()) - 1
        fargs, varargs, varkw, defaults = inspect.getargspec(func)
        if args.__len__() > func_args_len:
            func_args = args[:func_args_len]
            extra_args = args[func_args_len:]
            for dict_arg in extra_args:
                for k, v in dict_arg.iteritems():
                    kwargs[k] = v
            return func(*func_args, **kwargs)
        else:
            if (varkw == 'kwargs'):
                return func(*args, **kwargs)
            else:
                return func(*args)

    def create_network(self, context, network):
        """
        Perform this operation in the context of the configured device
        plugins.
        """
        try:
            args = [context, network]
            ovs_output = self._invoke_plugin_per_device(const.EDGE_PLUGIN,
                                                        self._func_name(),
                                                        args)
            vlan_id = odb.get_vlan(ovs_output[0]['id'])
            vlan_name = conf.VLAN_NAME_PREFIX + str(vlan_id)
            args = [ovs_output[0]['tenant_id'], ovs_output[0]['name'],
                    ovs_output[0]['id'], vlan_name, vlan_id]
            nexus_output = self._invoke_plugin_per_device(const.NEXUS_PLUGIN,
                                                          self._func_name(),
                                                          args)
            return ovs_output[0]
        except:
            # TODO (Sumit): Check if we need to perform any rollback here
            raise

    def update_network(self, context, id, network):
        """
        Perform this operation in the context of the configured device
        plugins.
        """
        try:
            args = [context, id, network]
            ovs_output = self._invoke_plugin_per_device(const.EDGE_PLUGIN,
                                                        self._func_name(),
                                                        args)
            return ovs_output[0]
        except:
            raise

    def delete_network(self, context, id, kwargs):
        """
        Perform this operation in the context of the configured device
        plugins.
        """
        try:
            base_plugin_ref = kwargs[const.BASE_PLUGIN_REF]
            n = kwargs[const.NETWORK]
            tenant_id = n['tenant_id']
            output = []
            args = [context, id]
            ovs_output = self._invoke_plugin_per_device(const.EDGE_PLUGIN,
                                                        self._func_name(),
                                                        args)
            args = [tenant_id, id, {const.CONTEXT:context},
                    {const.BASE_PLUGIN_REF:base_plugin_ref}]
            nexus_output = self._invoke_plugin_per_device(const.NEXUS_PLUGIN,
                                                          self._func_name(),
                                                          args)
            return ovs_output[0]
        except:
            raise

    def get_network(self, context, id, fields=None, verbose=None):
        """
        Perform this operation in the context of the configured device
        plugins.
        """
        try:
            args = [context, id, fields, verbose]
            ovs_output = self._invoke_plugin_per_device(const.EDGE_PLUGIN,
                                                        self._func_name(),
                                                        args)
            return ovs_output[0]
        except:
            raise

    def get_networks(self, context, filters=None, fields=None, verbose=None):
        """
        Perform this operation in the context of the configured device
        plugins.
        """
        try:
            args = [context, filters, fields, verbose]
            ovs_output = self._invoke_plugin_per_device(const.EDGE_PLUGIN,
                                                        self._func_name(),
                                                        args)
            return ovs_output[0]
        except:
            raise

    def create_port(self, context, port):
        """Currently there is no processing required for the device plugins"""
        pass

    def get_port(self, context, id, fields=None, verbose=None):
        """Currently there is no processing required for the device plugins"""
        pass

    def get_ports(self, context, filters=None, fields=None, verbose=None):
        """Currently there is no processing required for the device plugins"""
        pass

    def update_port(self, context, id, port):
        """Currently there is no processing required for the device plugins"""
        pass

    def delete_port(self, context, id, kwargs):
        """Currently there is no processing required for the device plugins"""
        pass

    def create_subnet(self, context, subnet):
        """Currently there is no processing required for the device plugins"""
        pass

    def update_subnet(self, context, id, subnet):
        """Currently there is no processing required for the device plugins"""
        pass

    def get_subnet(self, context, id, fields=None, verbose=None):
        """Currently there is no processing required for the device plugins"""
        pass

    def delete_subnet(self, context, id, kwargs):
        """Currently there is no processing required for the device plugins"""
        pass

    def get_subnets(self, context, filters=None, fields=None, verbose=None):
        """Currently there is no processing required for the device plugins"""
        pass
