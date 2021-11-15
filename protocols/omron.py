"""
OMRON FINS class.
All tools used for parsing, analyizing and logging Omron Fins packets.

G.Mellone, C.G.De Vita
Apr 2021
"""
import uuid
import time

from scapy.layers.inet import UDP, TCP
from config import *

from utils import Utils
from struct import unpack as unp

OMRON_TYPE = {
    0x80 : 'Command',
    0xc1 : 'Response'
}
OMORON_COMMAND_CODE ={
    0x0101: "Memory Area Read",
    0x0102: "Memory Area Write",
    0x0103: "Memory Area Fill",
    0x0104: "Multiple Memory Area Read",
    0x0105: "Memory Area Transfer",
    0x0201: "Parameter Area Read",
    0x0202: "Parameter Area Write",
    0x0203: "Parameter Area Clear",
    0x0220: "Data Link Table Read",
    0x0221: "Data Link Table Write",
    0x0304: "Program Area Protect",
    0x0305: "Program Area Protect Clear",
    0x0306: "Program Area Read",
    0x0307: "Program Area Write",
    0x0308: "Program Area Clear",
    0x0401: "Run",
    0x0402: "Stop",
    0x0403: "Reset",
    0x0501: "Controller Data Read",
    0x0502: "Connection Data Read",
    0x0601: "Controller Status Read",
    0x0602: "Network Status Read",
    0x0603: "Data Link Status Read",
    0x0620: "Cycle Time Read",
    0x0701: "Clock Read",
    0x0702: "Clock Write",
    0x0801: "LOOP-BACK Test",
    0x0802: "Broadcast Test Results Read",
    0x0803: "Broadcast Test Data Send",
    0x0920: "Message Read | Message Clear | FAL/FALS Read",
    0x0C01: "Access Right Acquire",
    0x0C02: "Access Right Forced Acquire",
    0x0C03: "Access Right Release",
    0x2101: "Error Clear",
    0x2102: "Error Log Read",
    0x2103: "Error Log Clear",
    0x2201: "File Name Read",
    0x2202: "Single File Read",
    0x2203: "Single File Write",
    0x2204: "Memory Card Format",
    0x2205: "File Delete",
    0x2206: "Volume Label Create/Delete",
    0x2207: "File Copy",
    0x2208: "File Name Change",
    0x2209: "File Data Check",
    0x220A: "Memory Area File Transfer",
    0x220B: "Parameter Area File Transfer",
    0x220C: "Program Area File Transfer",
    0x220F: "File Memory Index Read",
    0x2210: "File Memory Read",
    0x2211: "File Memory Write",
    0x2301: "Forced Set/Reset",
    0x2302: "Forced Set/Reset Cancel",
    0x230A: "Multiple Forced Status Read",
    0x2601: "Name Set",
    0x2602: "Name Delete",
    0x2603: "Name Read",
    0: None
}



class Omron(object):
    def is_omron(packet):
        if packet.haslayer('Raw'):
            _raw = bytes(packet['Raw'])
            u = unp('!B', _raw[:1])[0]
            if u == 0x80 or u == 0xc1:
                if packet.haslayer(UDP):
                    if packet[UDP].dport == OMRON_PORT:
                        return True
                    else:
                        return False
                if packet.haslayer(TCP):
                    if packet[TCP].dport == OMRON_PORT:
                        return True
                    else:
                        return False

    # Function used to parse packet into a OMRON JSON mode
    def parse(packet):
        # Convert packet from bytes to JSON
        _pkt = Utils.convert_json(packet)

        _raw = bytes(packet['Raw'])
        print(_raw)
        type = unp('!B', _raw[:1])[0]
        command_code = unp('!H', _raw[10:12])[0]
        command_data = ''
        if int(command_code) == 8961: # (0x2301)
            try:
                command_data = unp('!H', _raw[12:16])[0]
                print(hex(command_data))
            except:
                print("NA")


        parsed_packet = Utils.initializePacket('OMRON',packet)

        parsed_packet['OMRON_header'] = _raw
        parsed_packet['OMRON_type'] = hex(type)                                     # OMRON Packet type
        parsed_packet['OMRON_type_des'] = OMRON_TYPE[type]                          # OMRON Packet type des
        parsed_packet['OMRON_command_code'] = hex(command_code)
        parsed_packet['OMRON_command_code_des'] = OMORON_COMMAND_CODE[command_code]
        #parsed_packet['OMRON_command_data'] = hex(command_data)

        if EXPORT_RAW:
            parsed_packet['raw'] = _pkt

        # Return formatted JSON
        return parsed_packet

