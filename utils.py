#
# A group of useful functions
# G.Mellone, C.G.De Vita, Mar 2021
#
import uuid
import time

class Utils(object):

    @staticmethod
    def convert_json(packet):
        packet_dict = {}
        for line in packet.show2(dump=True).split('\n'):
            if '###' in line:
                layer = line.strip('|#[] ')
                packet_dict[layer] = {}
            elif '=' in line:
                key, val = line.split('=', 1)
                packet_dict[layer][key.strip(' |')] = val.strip()
        return packet_dict

    @staticmethod
    def convert_json_mod(packet):
        packet_dict = {}
        for line in packet.show2(dump=True).split('\n'):
            if '###' in line:
                layer = line.strip('|#[] ')
                layer = layer.replace(" ","")
                #packet_dict[layer] = {}
            elif '=' in line:
                key, val = line.split('=', 1)
                packet_dict[layer + "_" + key.strip(' |')] = val.strip()
        return packet_dict

    @staticmethod
    def initializePacket(protocol_name, packet):
        _pkt = Utils.convert_json(packet)

        parsed_packet = {
            'protocol': protocol_name,
            'uuid': str(uuid.uuid4()),  # Unique ID
            'timestamp': str(time.time()),  # Timestamp
        }

        if packet.haslayer("TCP"):
            parsed_packet['port_source'] = _pkt['TCP']['sport']  # Source Port Address
            parsed_packet['port_destination'] = _pkt['TCP']['dport']  # Destination Port Address

        if packet.haslayer("IP"):
            parsed_packet['ip_source'] = _pkt['IP']['src']  # Source IP Address
            parsed_packet['ip_destination'] = _pkt['IP']['dst']  # Destination IP Address

        if packet.haslayer("Ethernet"):
            parsed_packet['source'] = "Ethernet"
            parsed_packet['mac_source'] = _pkt['Ethernet']['src']  # Source MAC Address
            parsed_packet['mac_destination'] = _pkt['Ethernet']['dst']  # Destination MAC Address

        if packet.haslayer("Loopback"):
            parsed_packet['source'] = "Loopback"
            parsed_packet['mac_source'] = _pkt['Loopback']['type']  # Source MAC Address

        return parsed_packet