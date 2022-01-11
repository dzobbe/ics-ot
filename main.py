""" ICS-OT Tools

Python tool suite used to analyze packet traffic of different protocols:
    MODBUS-TCP
    DNP3
    PROFINET DCP
    SIEMENS S7
    OMRON
    LORAWAN
    ZIG-BEE
Tools used to parse packets to a JSON mode, search for attacks and create a full

"""
__authors__ = ["Gennaro Mellone", "Ciro Giuseppe De Vita"]
__contact__ = ["gennaro.mellone@uniparthenope.it", "cirogiuseppe.devita@uniparthenope.it"]
__copyright__ = ''
__credits__ = ''
__version__ = "1.0.5"
__status__ = "Development"


from argparse import ArgumentParser
from json import dumps

import config
import logstash
import logging

from lib.DNP3_Lib.DNP3_Lib import DNP3

from scapy.all import *
from scapy.config import conf
import scapy.contrib.modbus as mb

from scapy.layers.inet import UDP

from protocols.modbus import Modbus
from protocols.dnp3 import DNP3
from protocols.profinet import ProfinetDCP
from protocols.s7 import S7
from protocols.omron import Omron
from protocols.lorawan import LoraWan
from protocols.zigbee import ZigBee

from pymongo import MongoClient

from kafka import KafkaProducer


def initialize_logstash():
    logging.info("[GENERAL] Initializing Logstash on port " + str(config.LOGSTASH_PORT))
    logst = logging.getLogger('python-logstash-logger')
    logst.setLevel(logging.INFO)
    logst.addHandler(logstash.UDPLogstashHandler(config.LOGSTASH_HOST, config.LOGSTASH_PORT, version=1))

    return logst


def initialize_kafka():
    producer = KafkaProducer(bootstrap_servers=[config.BROKER_KAFKA],
                             value_serializer=lambda x: dumps(x).encode('utf-8'))

    return producer


"""
def initialize_mongo():
    logging.info("[GENERAL] Initializing MongoDB on " + str(config.DB_HOST))
    client = MongoClient(config.DB_HOST)
    db = client["icsotdb"]
    pk = db["packets"]

    return pk
"""


# General function to capture packets (Scapy Framework)
def capture(pkt):
    s = S7()
    parsed_pkt = ''
    # If DNP3 Packet found:
    if pkt.haslayer('DNP3'):
        parsed_pkt = DNP3.parse(pkt)

    # If Modbus REQUEST Packet found:
    elif mb.ModbusADURequest in pkt:
        # Parse packet into a JSON
        parsed_pkt = Modbus.parse(pkt)

    # If Profinet DCP Packet found:
    elif pkt.haslayer('ProfinetIO'):
        parsed_pkt = ProfinetDCP.parse(pkt)

    # If ARP  Packet found:
    elif pkt.haslayer('ARP'):
        parsed_pkt = ProfinetDCP.parseARP(pkt)

    # If Siemens S7 Packet found:
    elif s.is_s7(pkt):
        parsed_pkt = s.parse(packet=pkt)

    # If Omron Fins Packet found:
    elif Omron.is_omron(pkt):
        parsed_pkt = Omron.parse(packet=pkt)

    # Search for LoRaWAN Packets
    elif pkt.haslayer(UDP):
        if pkt[UDP].dport == config.LORA_PORT:
            parsed_pkt = LoraWan.parse(packet=pkt)

    # If ZigBee Packet found:
    elif pkt.haslayer('Zigbee Network Layer'):
        parsed_pkt = ZigBee.parse(packet=pkt)

    else:
        parsed_pkt = {
            'protocol': 'UNDEFINED'
        }

    try:
        if parsed_pkt['protocol'] != 'UNDEFINED':

            logging.info("[PACKET] " + str(parsed_pkt))

            # Print in Logstash
            logst.info('PACKET', extra=parsed_pkt)

            # Send to Kafka
            #kf.send(config.TOPIC_KAFKA, value=parsed_pkt)

            # Save in DB
            # mg.insert_one(parsed_pkt)
    except:
        pass


def main():
    # Load ArgumentParser to read command line arguments
    parser = ArgumentParser()

    # Read INTERFACE argument (Must be selected)
    parser.add_argument("-i", "--interface", dest="interface",
                        help="Select an interface or a PCAP file")

    # Log file path
    parser.add_argument("-l", "--log",
                        dest="log", default='icsot.log',
                        help="Insert log path")
    # Show RAW packages
    parser.add_argument("--show-raw",
                        dest="show_raw", action='store_true',
                        help="Show raw captured packages")

    args = parser.parse_args()
    interface = ""
    # Interface check
    if args.interface is not None:
        interface = args.interface
    else:
        #TODO Suggest all available interfaces
        logging.info("[ERROR] Should provide a valid interface!")
        exit(-1)

    # Load library for Profinet IO and DCP
    load_contrib('pnio')

    if args.show_raw:
        config.EXPORT_RAW = True

    # Start reading incoming packets
    if '.pcap' in args.interface or '.pcapng' in args.interface:
        logging.info("[GENERAL] PCAP File: " + interface)
        pkt = sniff(offline='pcap/' + interface, store=2, prn=capture)
    else:
        logging.info("[GENERAL] Interface: " + interface)
        pkt = sniff(iface=interface, store=2, prn=capture)

    logging.info("[GENERAL] Exiting " + str(pkt))


if __name__ == '__main__':
    # logging.basicConfig(filename=args.log, level=logging.INFO, format='%(asctime)s %(message)s')
    conf.dot15d4_protocol = 'zigbee'

    # Initialize logger
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    logging.info("[GENERAL] ICS-OT Tools")
    logging.info("[GENERAL] Version " + __version__)
    # mg = initialize_mongo()
    #kf = initialize_kafka()
    logst = initialize_logstash()
    print(get_if_list())
    main()
