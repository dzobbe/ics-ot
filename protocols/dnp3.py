from config import EXPORT_RAW
from utils import Utils


class DNP3:
    fir = 0
    fin = 0

    def parse(packet):

        # All DNP3 informations
        # ['', 'start', 'len', 'ctl', 'ctl_dir', 'ctl_prm', 'ctl_fcb', 'ctl_fcv',
        # 'ctl_prifunc', 'dst', 'addr', 'src', 'hdr_crc', 'dnp_hdr_crc_status',
        # 'tr_ctl', 'tr_fin', 'tr_fir', 'tr_seq', 'dnp_data_chunk', 'dnp_data_chunk_len',
        # 'dnp_data_chunk_crc', 'dnp_data_chunk_crc_status', 'al_fragments', 'al_fragment',
        # 'al_fragment_count', 'al_fragment_reassembled_length', 'al_ctl', 'al_fir', 'al_fin',
        # 'al_con', 'al_uns', 'al_seq', 'al_func', 'al_iin', 'al_iin_rst', 'al_iin_dt', 'al_iin_dol',
        # 'al_iin_tsr', 'al_iin_cls3d', 'al_iin_cls2d', 'al_iin_cls1d', 'al_iin_bmsg', 'al_iin_cc',
        # 'al_iin_oae', 'al_iin_ebo', 'al_iin_pioor', 'al_iin_obju', 'al_iin_fcni', '_ws_expert', 'iin_abnormal',
        # '_ws_expert_message', '_ws_expert_severity', '_ws_expert_group']

        parsed_packet = Utils.initializePacket('DNP3', packet)
        _pkt = Utils.convert_json(packet)

        if packet.haslayer("DNP3_Transport"):
            parsed_packet['DNP3_fir'] = packet.FIR  # FIR code
            parsed_packet['DNP3_fin'] = packet.FIN  # FIN code

        parsed_packet['DNP3_start'] = packet.START  # Start value (0x564)
        parsed_packet['DNP3_dfc'] = packet.CONTROL.FCV  # DFC control
        parsed_packet['DNP3_func_code'] = packet.FUNC_CODE  # FUNC_CODE
        parsed_packet['DNP3_func_code_des'] = _pkt['DNP3ApplicationControl']['FUNC_CODE']  # FUNC_CODE Description

        if EXPORT_RAW:
            parsed_packet['raw'] = _pkt

        return parsed_packet

