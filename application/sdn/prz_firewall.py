
from pox.core import core
import pox.openflow.libopenflow_01 as of
import time
from learning_firewall import learning_firewall


class prz_firewall(learning_firewall) :

    def __init__(self, connection):
        super(prz_firewall, self).__init__(connection)
        self.ws = ['100.0.0.40','100.0.0.41', '100.0.0.42']
        
    def _handle_PacketIn (self, event):

        packet = event.parsed 

        if event.port == 1: 
            if self.is_initial_packet(event): 
                self.block(event)
            else : 
                self.flood_learn(event)

        else : 
            if packet.find('ipv4') and packet.find('ipv4').dstip in self.ws and self.is_http_request(event): 
                self.flood_learn(event)

            elif packet.find('ipv4') and not packet.find('ipv4').dstip in self.ws: 
                self.flood_learn(event)

            elif packet.find('arp') : 
                self.flood_learn(event)
            else : 
                self.block(event)

