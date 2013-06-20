# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Cisco Systems, Inc.  All rights reserved.
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
# @author: Hareesh Puthalath, Cisco Systems, Inc.

import logging
import re

from ncclient import manager
from ncclient import xml_
import xml.etree.ElementTree as ET
from ciscoconfparse import CiscoConfParse


import cisco_csr_snippets as snippets


LOG = logging.getLogger(__name__)

# INTERNAL_INTFC = 'GigabitEthernet'
# SEP = '.'


class CiscoCSRDriver():
    """CSR1000v Driver Main Class."""
    def __init__(self, csr_host, csr_ssh_port, csr_user, csr_password):
        self._csr_host = csr_host
        self._csr_ssh_port = csr_ssh_port
        self._csr_user = csr_user
        self._csr_password = csr_password
        self._csr_conn = None
        self._allow_agent = False

    def _get_connection(self):
        """Make SSH connection to the CSR """
        try:
            if self._csr_conn:
                return self._csr_conn
            else:
                self._csr_conn = manager.connect(host=self._csr_host,
                                                 port=self._csr_ssh_port,
                                                 username=self._csr_user,
                                                 password=self._csr_password,
                                                 allow_agent=self._allow_agent)
                #self._csr_conn.async_mode = True
            return self._csr_conn
        except Exception:
            LOG.exception("Failed getting connecting to CSR1000v. "
                          "Conn.Params %s" % "localhost:8000:stack:cisco")

    def _get_interfaces(self):
        """
        :return: List of the interfaces
        """
        ioscfg = self.get_running_config()
        parse = CiscoConfParse(ioscfg)
        intfs_raw = parse.find_lines("^interface GigabitEthernet")
        #['interface GigabitEthernet1', 'interface GigabitEthernet2', 'interface GigabitEthernet0']
        intfs = []
        for line in intfs_raw:
            intf = line.strip().split(' ')[1]
            intfs.append(intf)
        LOG.info("Interfaces:%s" % intfs)
        return intfs

    def get_interface_ip(self, interface_name):
        """
        Get the ip address for an interface
        :param interface_name:
        :return: ip address as a string
        """
        ioscfg = self.get_running_config()
        parse = CiscoConfParse(ioscfg)
        children = parse.find_children("^interface %s" % interface_name)
        for line in children:
            if 'ip address' in line:
                ip_address = line.strip().split(' ')[2]
                LOG.info("IP Address:%s" % ip_address)
                return ip_address
            else:
                LOG.warn("Cannot find interface:" % interface_name)
                return None

    def get_vrfs(self):
        """
        :return: A list of vrf names as string
        """
        vrfs = []
        ioscfg = self.get_running_config()
        parse = CiscoConfParse(ioscfg)
        vrfs_raw = parse.find_lines("^ip vrf")
        for line in vrfs_raw:
            vrf_name = line.strip().split(' ')[2]  #   ['ip vrf <vrf-name>',....]
            vrfs.append(vrf_name)
        LOG.info("VRFs:%s" % vrfs)
        return vrfs

    def get_capabilities(self):
        conn = self._get_connection()
        capabilities = []
        for c in conn.server_capabilities:
            capabilities.append(c)
        LOG.debug("Server capabilities: %s" % capabilities)
        return capabilities

    def get_running_config(self):
        conn = self._get_connection()
        config = conn.get_config(source="running")
        if config:
            root = ET.fromstring(config._raw)
            running_config = root[0][0]
            #print running_config.text
            rgx = re.compile("\r*\n+")
            ioscfg = rgx.split(running_config.text)
            return ioscfg

    def set_interface(self, name, ip_address, mask):
        conn = self._get_connection()
        confstr = snippets.SET_INTC % (name, ip_address, mask)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        print rpc_obj

    def create_vrf(self, vrf_name):
        try:
            conn = self._get_connection()
            confstr = snippets.CREATE_VRF % vrf_name
            rpc_obj = conn.edit_config(target='running', config=confstr)
            if self._check_response(rpc_obj, 'CREATE_VRF'):
                LOG.info("VRF %s successfully created" % vrf_name)
        except Exception:
            LOG.exception("Failed creating VRF %s" % vrf_name)

    def remove_vrf(self, vrf_name):
        if vrf_name in self.get_vrfs():
            conn = self._get_connection()
            confstr = snippets.REMOVE_VRF % vrf_name
            rpc_obj = conn.edit_config(target='running', config=confstr)
            if self._check_response(rpc_obj, 'REMOVE_VRF'):
                LOG.info("VRF %s removed" % vrf_name)
        else:
            LOG.warning("VRF %s not present" % vrf_name)

    def create_subinterface(self, subinterface, vlan_id, vrf_name, ip, mask):
        conn = self._get_connection()
        if vrf_name not in self.get_vrfs():
            LOG.error("VRF %s not present" % vrf_name)
        confstr = snippets.CREATE_SUBINTERFACE % (subinterface, vlan_id,
                                                  vrf_name, ip, mask)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        print self._check_response(rpc_obj, 'CREATE_SUBINTERFACE')

    def remove_subinterface(self, subinterface, vlan_id, vrf_name, ip, mask):
        conn = self._get_connection()
        confstr = snippets.REMOVE_SUBINTERFACE % ( subinterface )
        rpc_obj = conn.edit_config(target='running', config=confstr)
        print self._check_response(rpc_obj, 'REMOVE_SUBINTERFACE')

    def _get_interface_cfg(self, interface):
        ioscfg = self.get_running_config()
        parse = CiscoConfParse(ioscfg)
        res = parse.find_children('interface '+interface)
        return res

    def nat_rules_for_internet_access(self, acl_no, network,
                                      netmask,
                                      inner_intfc,
                                      outer_intfc,
                                      vrf_name):
        conn = self._get_connection()
        #We acquire a lock on the running config and process the edits
        #as a transaction
        with conn.locked(target='running'):
            confstr = snippets.CREATE_ACL % (acl_no, network, netmask)
            rpc_obj = conn.edit_config(target='running', config=confstr)
            print self._check_response(rpc_obj, 'CREATE_ACL')

            confstr = snippets.SET_DYN_SRC_TRL_INTFC % (acl_no, outer_intfc, vrf_name)
            rpc_obj = conn.edit_config(target='running', config=confstr)
            print self._check_response(rpc_obj, 'CREATE_SNAT')

            confstr = snippets.SET_NAT % (inner_intfc, 'inside')
            rpc_obj = conn.edit_config(target='running', config=confstr)
            print self._check_response(rpc_obj, 'SET_NAT')

            confstr = snippets.SET_NAT % (outer_intfc, 'outside')
            rpc_obj = conn.edit_config(target='running', config=confstr)
            print self._check_response(rpc_obj, 'SET_NAT')
        # finally:
        #     conn.unlock(target='running')

    def remove_nat_rules_for_internet_access(self, acl_no,
                                             network,
                                             netmask,
                                             inner_intfc,
                                             outer_intfc,
                                             vrf_name):
        conn = self._get_connection()
        #We acquire a lock on the running config and process the edits
        #as a transaction
        with conn.locked(target='running'):
            confstr = snippets.REMOVE_ACL % acl_no
            rpc_obj = conn.edit_config(target='running', config=confstr)
            print self._check_response(rpc_obj, 'REMOVE_ACL')

            confstr = snippets.REMOVE_DYN_SRC_TRL_INTFC % (acl_no, outer_intfc, vrf_name)
            rpc_obj = conn.edit_config(target='running', config=confstr)
            print self._check_response(rpc_obj, 'REMOVE_DYN_SRC_TRL_INTFC')

            confstr = snippets.REMOVE_NAT % (inner_intfc, 'inside')
            rpc_obj = conn.edit_config(target='running', config=confstr)
            print self._check_response(rpc_obj, 'REMOVE_NAT inside')

            confstr = snippets.REMOVE_NAT % (outer_intfc, 'outside')
            rpc_obj = conn.edit_config(target='running', config=confstr)
            print self._check_response(rpc_obj, 'REMOVE_NAT outside')

    def add_floating_ip(self, floating_ip, fixed_ip, vrf):
        conn = self._get_connection()
        confstr = snippets.SET_STATIC_SRC_TRL % (fixed_ip, floating_ip, vrf)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        print self._check_response(rpc_obj, 'SET_STATIC_SRC_TRL')

    def remove_floating_ip(self, floating_ip, fixed_ip, vrf):
        conn = self._get_connection()
        confstr = snippets.REMOVE_STATIC_SRC_TRL % (fixed_ip, floating_ip, vrf)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        print self._check_response(rpc_obj, 'REMOVE_STATIC_SRC_TRL')

    def _get_floating_ip_cfg(self):
        ioscfg = self.get_running_config()
        parse = CiscoConfParse(ioscfg)
        res = parse.find_lines('ip nat inside source static')
        return res

    def add_static_route(self, dest, dest_mask, next_hop, vrf):
        conn = self._get_connection()
        confstr = snippets.SET_IP_ROUTE % (vrf, dest, dest_mask, next_hop)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        print self._check_response(rpc_obj, 'SET_IP_ROUTE')

    def remove_static_route(self, dest, dest_mask, next_hop, vrf):
        conn = self._get_connection()
        confstr = snippets.REMOVE_IP_ROUTE % (vrf, dest, dest_mask, next_hop)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        print self._check_response(rpc_obj, 'REMOVE_IP_ROUTE')

    def _get_static_route_cfg(self):
        ioscfg = self.get_running_config()
        parse = CiscoConfParse(ioscfg)
        res = parse.find_lines('ip route')
        return res

    def _check_response_E(self, rpc_obj, snippet_name):
        #ToDo(Hareesh): This is not working. Need to be fixed
        LOG.debug("RPCReply for %s is %s" % (snippet_name, rpc_obj.xml))
        if rpc_obj.ok:
            return True
        else:
            raise rpc_obj.error

    def _check_response(self, rpc_obj, snippet_name):
        LOG.debug("RPCReply for %s is %s" % (snippet_name, rpc_obj.xml))
        xml_str = rpc_obj.xml
        if "<ok />" in xml_str:
            return True
        else:
            """
            Response in case of error looks like this.
            We take the error type and tag.
            '<?xml version="1.0" encoding="UTF-8"?>
            <rpc-reply message-id="urn:uuid:81bf8082-ccf1-11e2-b69a-000c29e1b85c"
            xmlns="urn:ietf:params:netconf:base:1.0">
                <rpc-error>
                    <error-type>protocol</error-type>
                    <error-tag>operation-failed</error-tag>
                    <error-severity>error</error-severity>
                </rpc-error>
            </rpc-reply>'
            """
            error_str = ("Error executing snippet %s "
                         "ErrorType:%s ErrorTag:%s ")
            logging.error(error_str, snippet_name, rpc_obj._root[0][0].text,
                          rpc_obj._root[0][1].text)
            raise Exception("Error!")


##################
#Main
##################

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, filemode="w")
    driver = CiscoCSRDriver("localhost", 8000, "stack", 'cisco')
    if driver._get_connection():
        logging.info('Connection Established!')
        driver.get_capabilities()
        #print driver.get_running_config(conn)
        #driver.set_interface(conn, 'GigabitEthernet1', '10.0.200.1')
        #driver.get_interfaces(conn)
        #driver.get_interface_ip(conn, 'GigabitEthernet1')
        driver.create_vrf('qrouter-dummy')
        #driver.get_vrfs(conn)
        #driver.create_router(1, 'qrouter-dummy2', '10.0.110.1', 11)
        #driver.create_subinterface('GigabitEthernet1.11', 'qrouter-131666dc', '10.0.11.1', '11', '255.255.255.0')
        #driver.remove_subinterface('GigabitEthernet1.11', 'qrouter-131666dc', '10.0.11.1', '11', '255.255.255.0')

        #driver.nat_rules_for_internet_access('acl_230', '10.0.230.0', '0.0.0.255',
        #                                     'GigabitEthernet1.230', 'GigabitEthernet2.230',
        #                                     'qrouter-dummy')
        #driver.remove_nat_rules_for_internet_access('acl_230', '10.0.230.0', '0.0.0.255',
        #                                     'GigabitEthernet1.230', 'GigabitEthernet2.230',
        #                                     'qrouter-dummy')

        #driver.add_floating_ip('192.168.0.2', '10.0.10.2', 'qrouter-131666dc')
        #driver.remove_floating_ip('192.168.0.2', '10.0.10.2', 'qrouter-131666dc')
        #driver.add_static_route('172.16.0.0', '255.255.0.0', '10.0.20.254', 'qrouter-131666dc')
        #driver.remove_static_route('172.16.0.0', '255.255.0.0', '10.0.20.254', 'qrouter-131666dc')
        #driver.remove_vrf('wrong_vrf') #Wrong vrf
        #driver.create_vrf("my_dummy_vrf")
        #driver.remove_vrf("my_dummy_vrf")
        #driver._get_floating_ip_cfg()

        print "All done"
