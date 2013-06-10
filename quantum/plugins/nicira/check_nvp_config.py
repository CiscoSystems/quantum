# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Nicira, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless equired by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
#
# @author: Aaron Rosen, VMware

import sys

from oslo.config import cfg

from quantum.common import config
from quantum.plugins.nicira.common import config as nvp_cfg  # noqa
from quantum.plugins.nicira import nvplib
from quantum.plugins.nicira import QuantumPlugin

config.setup_logging(cfg.CONF)


def help(name):
    print "Usage: %s path/to/nvp.ini" % name
    sys.exit(1)


def get_gateway_services(cluster):
    ret_gw_services = {"L2GatewayServiceConfig": [],
                       "L3GatewayServiceConfig": []}
    gw_services = nvplib.get_gateway_services(cluster).get('results', [])
    for gw_service in gw_services:
        ret_gw_services[gw_service['type']].append(gw_service['uuid'])
    return ret_gw_services


def get_transport_zones(cluster):
    transport_zones = nvplib.get_transport_zones(cluster).get('results')
    return [transport_zone['uuid'] for transport_zone in transport_zones]


def main(argv):
    if len(argv) != 2:
        help(argv[0])
    args = ['--config-file']
    args.append(argv[1])
    config.parse(args)
    print "------------------------ Database Options ------------------------"
    print "\tsql_connection: %s" % cfg.CONF.DATABASE.sql_connection
    print "\treconnect_interval: %d" % cfg.CONF.DATABASE.reconnect_interval
    print "\tsql_max_retries: %d" % cfg.CONF.DATABASE.sql_max_retries
    print "------------------------    NVP Options   ------------------------"
    print "\tNVP Generation Timeout %d" % cfg.CONF.NVP.nvp_gen_timeout
    print ("\tNumber of concurrent connections to each controller %d" %
           cfg.CONF.NVP.concurrent_connections)
    print "\tmax_lp_per_bridged_ls: %s" % cfg.CONF.NVP.max_lp_per_bridged_ls
    print "\tmax_lp_per_overlay_ls: %s" % cfg.CONF.NVP.max_lp_per_overlay_ls
    print ("\tenable_metadata_access_network: %s" %
           cfg.CONF.NVP.enable_metadata_access_network)
    print "------------------------  Cluster Options ------------------------"
    print "\trequested_timeout: %s" % cfg.CONF.req_timeout
    print "\tretries: %s" % cfg.CONF.retries
    print "\tredirects: %s" % cfg.CONF.redirects
    print "\thttp_timeout: %s" % cfg.CONF.http_timeout
    cluster = QuantumPlugin.create_nvp_cluster(
        cfg.CONF,
        cfg.CONF.NVP.concurrent_connections,
        cfg.CONF.NVP.nvp_gen_timeout)
    num_controllers = len(cluster.nvp_controllers)
    print "Number of controllers found: %s" % num_controllers
    if num_controllers == 0:
        print "You must specify at least one controller!"
        sys.exit(1)

    for controller in cluster.nvp_controllers:
        print "\tController endpoint: %s" % controller
        nvplib.check_cluster_connectivity(cluster)
        gateway_services = get_gateway_services(cluster)
        for svc_type in ["L2GatewayServiceConfig",
                         "L3GatewayServiceConfig"]:
            for uuid in gateway_services[svc_type]:
                print "\t\tGateway(%s) uuid: %s" % (svc_type, uuid)
        transport_zones = get_transport_zones(cluster)
        print "\tTransport zones: %s" % transport_zones
    print "Done."
