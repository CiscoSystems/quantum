PORT_VLAN_SET_FLOW_XML ="""
<flowConfig>
    <node id="%s" type="OF" />
    <ingressPort>%s</ingressPort>
    <name>%s</name>
    <actions>setVlan=%s</actions>
</flowConfig>
"""
