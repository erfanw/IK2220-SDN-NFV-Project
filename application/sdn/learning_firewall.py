
from pox.core import core
import pox.openflow.libopenflow_01 as of
import time
from pox.forwarding.l2_learning import LearningSwitch
from pox.lib.packet import arp

log = core.getLogger()

class learning_firewall(LearningSwitch) : 

    def __init__(self, connection):

        LearningSwitch.__init__(self, connection,False)
        

    def flood_learn(self, event): 

        super(learning_firewall, self)._handle_PacketIn(event)
        
    def block(self, event) : 

        packet = event.parsed
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        self.connection.send(msg)

    def is_initial_packet(self, event) : 
        packet = event.parsed 
        if packet.find ('ipv4') : 
            ipv4 = packet.find('ipv4')
            if ipv4.protocol == ipv4.TCP_PROTOCOL : 
                tcp = packet.find('tcp')
                if tcp.ack == 0 : 
                    return True

            elif ipv4.protocol == ipv4.ICMP_PROTOCOL : 
                icmp = packet.find('icmp')
                if icmp.type == 8: 
                    return True 
        return False

    def is_http_request(self, event): 
        packet = event.parsed
        if packet.find('tcp'): 
            tcp = packet.find('tcp')
            if tcp.dstport == 80 : 
                return True
        return False





