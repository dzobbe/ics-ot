"""
MODBUS TCP class.
All tools used for parsing, analyizing and logging Modbus packets.

G.Mellone, C.G.De Vita
Mar 2021
"""
from config import EXPORT_RAW
from utils import Utils


class Modbus:

# Function used to parse packet into a Modbus JSON mode
    def parse(packet):
        # Convert packet from bytes to JSON
        _pkt = Utils.convert_json(packet)

        # Get Modbus Packet's function name
        modbus_info_type = list(_pkt)[4]

        # Get Modbus Type string
        modbus_type = list(_pkt)[3]

        # Initialize packet with main informations (IP, TCP, uuid, etc)
        parsed_packet = Utils.initializePacket('ModbusTCP', packet)

        parsed_packet['ModbusTCP_func_name'] = modbus_info_type                    # Modbus Function name
        parsed_packet['ModbusTCP_func_code'] = _pkt[modbus_info_type]['funcCode']  # Modbus Function code
        parsed_packet['ModbusTCP_data'] = _pkt[modbus_info_type]                   # Modbus extra data
        parsed_packet['ModbusTCP_trans_id'] = _pkt[modbus_type]['transId']         # Modbus ID transaction
        parsed_packet['ModbusTCP_prot_id'] = _pkt[modbus_type]['protoId']          # Modbus Protocol ID
        parsed_packet['ModbusTCP_len'] = _pkt[modbus_type]['len']                  # Modbus Len
        parsed_packet['ModbusTCP_unit_id'] = _pkt[modbus_type]['unitId']           # Modbus Unit ID

        if EXPORT_RAW:
            parsed_packet['raw'] = _pkt                                         # Raw Packet

        # Return formatted JSON
        return parsed_packet
