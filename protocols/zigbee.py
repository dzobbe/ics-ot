from utils import Utils
from config import EXPORT_RAW


class ZigBee:
    # ZBEE PACKET

    # NWK
    # ['fcf', 'frame_type', 'proto_version', 'discovery', 'multicast', 'security',
    # 'src_route', 'ext_dst', 'ext_src', 'end_device_initiator', 'dst', 'addr', 'src',
    # 'radius', 'seqno', 'dst64', 'addr64', 'src64', '', 'zbee_sec_field', 'zbee_sec_key_id',
    # 'zbee_sec_ext_nonce', 'zbee_sec_counter', 'zbee_sec_src64', 'zbee_sec_key_seqno', 'zbee_sec_mic',
    # 'zbee_sec_key', 'zbee_sec_key_origin']

    # ZCL
    # ['', 'type', 'ms', 'dir', 'ddr', 'cmd_tsn']

    # APS
    # ['', 'type', 'delivery', 'ack_format', 'security', 'ack_req',
    # 'ext_header', 'dst', 'cluster', 'profile', 'src', 'counter']

    def parse(packet):
        parsed_packet = Utils.initializePacket('ZigBee', packet)

        _pkt = Utils.convert_json_mod(packet)

        parsed_packet.update(_pkt)

        if EXPORT_RAW:
            parsed_packet['raw'] = _pkt

        return parsed_packet
