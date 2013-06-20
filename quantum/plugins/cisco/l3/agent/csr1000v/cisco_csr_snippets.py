# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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

"""
CSR (IOS-XE) XML-based configuration snippets
"""

#import logging


#LOG = logging.getLogger(__name__)


# The standard Template used to interact with IOS-XE(CSR),
# EXEC_CONF_SNIPPET = """
#       <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
#         <configure>
#           <__XML__MODE__exec_configure>%s
#           </__XML__MODE__exec_configure>
#         </configure>
#       </config>
# """

SHOW_CONF = """
    <get-config>
        <source>
            <running/>
        </source>
         <filter>
            <config-format-text-block>
                 <text-filter-spec> | inc interface </text-filter-spec>
            </config-format-text-block>
        </filter>
    </get-config>

"""

GET_INFC = """
<filter>
    <config-format-text-block>
        <text-filter-spec> | inc interface </text-filter-spec>
    </config-format-text-block>
</filter>

"""

CONFIG = """
 <config-format-text-block>
        <text-filter-spec> | inc interface </text-filter-spec>
    </config-format-text-block>
"""

SET_INTC = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>ip address %s %s</cmd>
        </cli-config-data>
</config>
"""

CREATE_VRF = """
<config>
        <cli-config-data>
            <cmd>ip routing</cmd>
            <cmd>ip vrf %s</cmd>
        </cli-config-data>
</config>
"""

REMOVE_VRF = """
<config>
        <cli-config-data>
            <cmd>ip routing</cmd>
            <cmd>no ip vrf %s</cmd>
        </cli-config-data>
</config>
"""

CREATE_SUBINTERFACE = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>encapsulation dot1Q %s</cmd>
            <cmd>ip vrf forwarding %s</cmd>
            <cmd>ip address %s %s</cmd>
        </cli-config-data>
</config>

"""
REMOVE_SUBINTERFACE = """
<config>
        <cli-config-data>
            <cmd>no interface %s</cmd>
        </cli-config-data>
</config>

"""

CREATE_ACL = """
<config>
        <cli-config-data>
            <cmd>ip access-list standard %s</cmd>
            <cmd>permit %s %s</cmd>
        </cli-config-data>
</config>
"""

REMOVE_ACL = """
<config>
        <cli-config-data>
            <cmd>no ip access-list standard %s</cmd>
            </cli-config-data>
</config>
"""



SET_DYN_SRC_TRL_INTFC = """
<config>
        <cli-config-data>
            <cmd>ip nat inside source list %s interface %s vrf %s overload</cmd>
        </cli-config-data>
</config>

"""

REMOVE_DYN_SRC_TRL_INTFC = """
<config>
        <cli-config-data>
            <cmd>no ip nat inside source list %s interface %s vrf %s overload</cmd>
        </cli-config-data>
</config>

"""

SET_NAT = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>ip nat %s</cmd>
        </cli-config-data>
</config>
"""

REMOVE_NAT = """
<config>
        <cli-config-data>
            <cmd>interface %s</cmd>
            <cmd>no ip nat %s</cmd>
        </cli-config-data>
</config>
"""

SET_STATIC_SRC_TRL = """
<config>
        <cli-config-data>
            <cmd>ip nat inside source static %s %s vrf %s </cmd>
        </cli-config-data>
</config>

"""

REMOVE_STATIC_SRC_TRL = """
<config>
        <cli-config-data>
            <cmd>no ip nat inside source static %s %s vrf %s </cmd>
        </cli-config-data>
</config>

"""

#ip route vrf <vrf-name> <destination> <mask> [<interface>] <next hop>
SET_IP_ROUTE = """
<config>
        <cli-config-data>
            <cmd>ip route vrf %s %s %s %s</cmd>
        </cli-config-data>
</config>
"""

REMOVE_IP_ROUTE = """
<config>
        <cli-config-data>
            <cmd>no ip route vrf %s %s %s %s</cmd>
        </cli-config-data>
</config>
"""