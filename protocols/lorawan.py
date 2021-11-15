"""
LoRaWAN class.
All tools used for parsing, analyizing and logging LoRaWAN packets.

G.Mellone, C.G.De Vita
Nov 2021
"""
from lib.lorawan.loraphy2wan import LoRa
from scapy.layers.inet import UDP
from utils import Utils
from config import EXPORT_RAW

class LoraWan(object):
    def parse(packet):

        # Decode LoRaPHY packet with library
        decoded = LoRa(packet[UDP].load)
        try:
            # Initialize parsing
            parsed_packet = Utils.initializePacket('LoRaWan', packet)

            # Convert to JSON format
            _pkt = Utils.convert_json_mod(decoded)

            # Merge LoRa packet's information with default packet's informations
            parsed_packet.update(_pkt)

            # If enabled, return a RAW value
            if Utils.export_raw:
                parsed_packet['raw'] = _pkt

        except:
            parsed_packet = Utils.initializePacket('LoRaWan', packet)

            if EXPORT_RAW:
                parsed_packet['raw'] = _pkt

        return parsed_packet