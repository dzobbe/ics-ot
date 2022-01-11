"""
SIEMENS S7 class.
All tools used for parsing, analyizing and logging Siemens S7 packets.

G.Mellone, C.G.De Vita
Apr 2021
"""

from scapy.layers.inet import TCP

from utils import Utils
from config import *
import binascii

HEADER_PACKET_TYPE = {
        '31': 'Request',
        '32': 'Response',
        '33': 'Keep-alive or cyclic',
        '': 'N/A'
    }
HEADER_ROSCTR_TYPE = {      # PDU type
    '': 'N/A',
    '01': 'Job',
    '02': 'Ack',
    '03': 'Ack_Data',
    '07': 'Userdata',
    }
PARAMETERS_FUNCTION_CODE = {      # Function Codes
    '00': 'CPU services',
    'f0': 'Setup communication',
    '04': 'Read Var',
    '05': 'Write Var',
    '1a': 'Request download',
    '1b': 'Download block',
    '1c': 'Download ended',
    '1d': 'Start upload',
    '1e': 'Upload',
    '1f': 'End upload',
    '28': 'PI-Service',
    '29': 'PLC Stop',
    '': 'N/A'
}
HEADER_ERROR_INFO = {      # Error info
    '': 'N/A',
    '00': 'No error',
    '81': 'Application relationship error',
    '82': 'Object definition error',
    '83': 'No ressources available error',
    '84': 'Error on service processing',
    '85': 'Error on supplies',
    '87': 'Access error'
    }
HEADER_ERROR_CODES = {
    '': 'N/A',
    '0000': 'No error',
    '0110': 'Invalid block type number',
    '0112': 'Invalid parameter',
    '011A': 'PG resource error',
    '011B': 'PLC ressource error',
    '011C': 'Protocol error',
    '011F': 'User buffer too short',
    '0141': 'Request error',
    '01C0': 'Version mismatch',
    '01F0': 'Not implemented',
    '8001': 'L7 invalid CPU state',
    '8500': 'L7 PDU size error',
    'D401': 'L7 invalid SZL ID',
    'D402': 'L7 invalid index',
    'D403': 'L7 DGS Connection already announced',
    'D404': 'L7 Max user NB',
    'D405': 'L7 DGS function parameter syntax error',
    'D406': 'L7 no info',
    'D601': 'L7 PRT function parameter syntax error',
    'D801': 'L7 invalid variable address',
    'D802': 'L7 unknown request',
    'D803': 'L7 invalid request status'
}
# PARAMETERS
# FUNCTION TYPES
USERDATA_PARAMETERS_FUNCTION = {      # Error info
    '': 'N/A',
    '1': 'Programmer commands',
    '2': 'Cyclic data',
    '3': 'Block functions',
    '4': 'CPU functions',
    '5': 'Security',
    '7': 'Time functions'
    }
USERDATA_PARAMETERS_SUBFUNCTION = {      # Error info
    '': {'': 'N/A'},
    '1': {
        '01': 'Request diag data (Type 1)',
        '02': 'VarTab',
        '0C': 'Erase',
        '0E': 'Read diag data',
        '0F': 'Remove diag data',
        '10': 'Forces',
        '13': 'Request diag data (Type2)'
    },
    '2': {
        '01': 'Memory',
        '04': 'Unsubscribe',
    },
    '3': {
        '01': 'List blocks',
        '02': 'List blocks of type',
        '03': 'Get block info',
    },
    '4': {
        '01': 'Read SZL',
        '02': 'Message service',
        '03': 'Transition to stop',
        '0B': 'Alarm was acknowledged in HMI / SCADA 1',
        '0C': 'Alarm was acknowledged in HMI/SCADA 2',
        '11': 'PLC is indicating a ALARM message',
        '13': 'HMI/SCADA initiating ALARM subscription',
    },
    '5': {
        '01': 'PLC password'
    },
    '7': {
        '01': 'Read clock',
        '02': 'Set clock',
        '03': 'Read clock (following)',
        '04': 'Set clock'
    }
}

class S7(object):

    def is_s7(self, packet):

        if packet.haslayer(TCP):
            if packet[TCP].dport == S7_PORT:
                pkt = binascii.hexlify(bytes(packet[TCP].payload))
                pkt = str(pkt.decode('utf-8'))
                try:
                    a, b, s = self.__parse_payload(pkt)
                    if s[:2] in HEADER_PACKET_TYPE:
                        return True
                    else:
                        return False
                except:
                    pass


    @staticmethod
    def __wrapperS7(raw):
        func_code = ''
        userdata_func_code = ''
        userdata_subfunc_code = ''
        protocol_id = raw[:2]
        rosctr = raw[2:4]

        data_length = int(raw[16:20], 16)

        if rosctr == '03': #If ROSCTR is ACK_DATA, contains error info
            err_info = raw[20:22]
            err_code = raw[22:24]
            err_info_des = HEADER_ERROR_INFO[str(err_info)]

        else:
            err_info = ''
            err_code = ''
            err_info_des = ''

        _parameter = raw[20:36]

        # If USERDATA
        if rosctr == '07':
            req = _parameter[8:10]
            userdata_func_code = _parameter[11:12]
            userdata_subfunc_code = _parameter[12:14]

        if rosctr == '01' or rosctr == '03':    # If rosctr is JOB or ACK_DATA, contains a Function Code
            func_code = _parameter[:2]

        _data = raw[36:]

        return {
            'protocol_id': protocol_id,
            'protocol_id_des': HEADER_PACKET_TYPE[str(protocol_id)],
            'rosctr': rosctr,
            'rosctr_des': HEADER_ROSCTR_TYPE[str(rosctr)],
            'data_length': data_length,
            'err_info': err_info,
            'err_info_des': err_info_des,
            'err_code': err_code,
            'err_code_des': HEADER_ERROR_CODES[str(err_code)],
            'func_code': func_code,
            'func_des': PARAMETERS_FUNCTION_CODE[str(func_code)],
            'userdata_func_code': userdata_func_code,
            'userdata_func_des': USERDATA_PARAMETERS_FUNCTION[str(userdata_func_code)],
            'userdata_subfunc_code': userdata_subfunc_code,
            'userdata_subfunc_des': USERDATA_PARAMETERS_SUBFUNCTION[str(userdata_func_code)][str(userdata_subfunc_code)]

        }

    def __parse_payload(self, payload):
        if len(payload) >= 4 * 2:
            tpkt = payload[:4] == '0300' and payload[:8] or ''
            if len(payload) >= 7 * 2:
                # self.cotp = self.payload[8:12] == '02f0' and self.payload[8:14] or ''
                cotp = payload[8:14] or ''
                if len(payload) > 8 * 2:
                    data = payload[14:]
                    if '31' <= data[:2] <= '33':
                        s7 = data
                        return tpkt, cotp, s7
                    else:
                        cotp += data
                        return tpkt, cotp, 0

    def parse(self, packet):
        pkt = binascii.hexlify(bytes(packet[TCP].payload))
        pkt = str(pkt.decode('utf-8'))
        _pkt = Utils.convert_json(packet)

        try:
            a, b, s = self.__parse_payload(pkt)

            #print('TPKT', a)
            #print('COTP', b)
            #print('S7', s)
            _s7 = self.__wrapperS7(s)

            parsed_packet = Utils.initializePacket('S7', packet)

            parsed_packet['S7_protocol_id'] = _s7['protocol_id']
            parsed_packet['S7_protocol_id_des'] = _s7['protocol_id_des']
            parsed_packet['S7_rosctr'] = _s7['rosctr']
            parsed_packet['S7_rosctr_des'] = _s7['rosctr_des']
            parsed_packet['S7_data_length'] = _s7['data_length']
            parsed_packet['S7_err_info'] = _s7['err_info']
            parsed_packet['S7_err_info_des'] = _s7['err_info_des']
            parsed_packet['S7_err_code'] = _s7['err_code']
            parsed_packet['S7_err_code_des'] = _s7['err_code_des']
            parsed_packet['S7_func_code'] = _s7['func_code']
            parsed_packet['S7_func_des'] = _s7['func_des']
            parsed_packet['S7_userdata_func_code'] = _s7['userdata_func_code']
            parsed_packet['S7_userdata_func_des'] = _s7['userdata_func_des']
            parsed_packet['S7_userdata_subfunc_code'] = _s7['userdata_subfunc_code']
            parsed_packet['S7_userdata_subfunc_des'] = _s7['userdata_subfunc_des']

            if EXPORT_RAW:
                parsed_packet['raw'] = _pkt

            return parsed_packet


        except Exception as e:
            print("Wrong Packet!")
            pass