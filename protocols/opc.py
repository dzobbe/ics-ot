import uuid
import time
#TODO NOT COMPLETED OPC
class OPC:
    def parse(packet):

        print(packet.opc.field_names)


        return {
            'uuid': str(uuid.uuid4()),
            'timestamp': str(time.time()),
            'address': packet.ip.addr,
            'source': packet.ip.src,
            'destination': packet.ip.dst,
            'opc': {

            }

        }
