SLICE_CREATE_XML = """
<sliceConfig>
  <slice>%s</slice>
  <staticVlan>%s</staticVlan>
</sliceConfig>
"""

ADD_SLICE_PORT_XML = """
<sliceConfig>
  <slice>%s</slice>
  <nodeId>%s</nodeId>
  <ports>%s</ports>
</sliceConfig>
"""
