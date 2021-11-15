
from utils import Utils
from config import EXPORT_RAW




class ProfinetDCP:
    # Function used to parse packet into a Profinet JSON mode
    def parse(packet):
        parsed_packet = Utils.initializePacket('ProfinetDCP', packet)

        _pkt = Utils.convert_json_mod(packet)

        parsed_packet.update(_pkt)

        '''
        # Convert packet from bytes to JSON
        _pkt = Utils.convert_json(packet)
        profinetDCP = _pkt['Profinet DCP']

        parsed_packet = Utils.initializePacket('Profinet DCP', packet)

        parsed_packet['pndcp_service_id'] = profinetDCP['service_id']
        parsed_packet['pndcp_service_type'] = profinetDCP['service_type']
        parsed_packet['pndcp_service_type'] = profinetDCP['xid']

        if profinetDCP['service_id'] == 'Identify' and 'Success' in profinetDCP['service_type']:

            parsed_packet['pndcp_deviceVendorValue'] = _pkt['DCPManufacturerSpecificBlock']['device_vendor_value']
            parsed_packet['pndcp_nameOfStation'] = _pkt['DCPNameOfStationBlock']['name_of_station']
            parsed_packet['pndcp_deviceID'] = _pkt['DCPDeviceIDBlock']['device_id']
            parsed_packet['pndcp_vendorID'] = _pkt['DCPDeviceIDBlock']['vendor_id']
            parsed_packet['pndcp_deviceRole'] = _pkt['DCPDeviceRoleBlock']['device_role_details']
            parsed_packet['pndcp_blockInfo'] = _pkt['DCPIPBlock']['block_info']
            parsed_packet['pndcp_blockIP'] = _pkt['DCPIPBlock']['ip']
        '''
        if EXPORT_RAW:
            parsed_packet['raw'] = _pkt

        return parsed_packet

    def parseARP(packet):
        parsed_packet = Utils.initializePacket('ARP', packet)

        _pkt = Utils.convert_json_mod(packet)

        parsed_packet.update(_pkt)

        '''
        parsed_packet['arp_operation'] = _pkt['ARP']['op']
        parsed_packet['arp_hwSrc'] = _pkt['ARP']['hwsrc']
        parsed_packet['arp_pSrc'] = _pkt['ARP']['psrc']
        parsed_packet['arp_hwDst'] = _pkt['ARP']['hwdst']
        parsed_packet['arp_pDst'] = _pkt['ARP']['pdst']
        '''
        if EXPORT_RAW:
            parsed_packet['raw'] = _pkt

        return parsed_packet