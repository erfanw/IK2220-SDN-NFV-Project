import pox.openflow.libopenflow_01 as of
import time
from learning_firewall import learning_firewall 
from pox.lib.addresses import IPAddr

class pbz_firewall(learning_firewall) : 

    def __init__(self, connection):
        super(pbz_firewall, self).__init__(connection)
        self.ws = ['100.0.0.40','100.0.0.41', '100.0.0.42']
        self.lb = '100.0.0.45'
        self.napt = '100.0.0.1'

    def _handle_PacketIn (self, event):

        packet = event.parsed 
        if event.port == 1 : 
            
            # ipv4 packet and neither targeting to lb nor ws
            if packet.find('ipv4') and packet.find('ipv4').dstip !=  self.lb and not packet.find('ipv4').dstip in self.ws: 
                self.flood_learn(event)

            elif packet.type == packet.ARP_TYPE and (packet.payload.protodst == self.lb or packet.payload.protodst == self.napt): 
                self.flood_learn(event)

            #ipv4 packet and toward lb
            elif packet.find('ipv4') and packet.find('ipv4').dstip == self.lb and self.is_http_request(event): 
                self.flood_learn(event)

            #icmp and toward lb
            elif packet.find('icmp') and packet.find('ipv4').dstip == self.lb: 
                self.flood_learn(event)

            else : 
                self.block(event)


        else : 
            self.flood_learn(event)



        


