
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import OVSSwitch
from mininet.node import RemoteController
import os


class MyTopo(Topo) :

    def __init__(self):
        Topo.__init__(self)

        #hosts
        h1 = self.addHost('h1', ip = '100.0.0.10/24')
        h2 = self.addHost('h2', ip = '100.0.0.11/24')
        h3 = self.addHost('h3', ip = '10.0.0.50/24')
        h4 = self .addHost('h4', ip = '10.0.0.51/24')
        #web servers
        wsw1 = self.addHost('ws1', ip = '100.0.0.40/24')
        wsw2 = self.addHost('ws2', ip = '100.0.0.41/24')
        wsw3 = self.addHost('ws3', ip = '100.0.0.42/24')
        #switches
        sw1 = self.addSwitch('sw1')
        sw2 = self.addSwitch('sw2')
        sw3 = self.addSwitch('sw3')
        sw4 = self.addSwitch('sw4')
        #firewall
        fw1 = self.addSwitch('fw1', dpid = '5')
        fw2 = self.addSwitch('fw2', dpid = '6')
        #network address translator
        napt = self.addSwitch('napt', dpid = '7')
        #load balancer
        lb = self.addSwitch('lb', dpid = '8')
# intrusion detection system
        ids = self.addSwitch('ids', dpid = '9')
        # inspector server
        insp = self.addHost('insp', ip = '100.0.0.30/24')
            #links#

        #public zone
        self.addLink(h1, sw1, port1 = 0, port2 = 1)
        self.addLink(h2, sw1, port1 = 0, port2 = 2)
        #private zone
        self.addLink(h3, sw3, port1 = 0, port2 = 1)
        self.addLink(h4, sw3, port1 = 0, port2 = 2)
        #demilitarized zone
        self.addLink(sw4, wsw1, port1 = 1, port2 = 0)
        self.addLink(sw4, wsw2, port1 = 2, port2 = 0)
        self.addLink(sw4, wsw3, port1 = 3, port2 = 0)
        self.addLink(sw4, lb, port1 = 4, port2 = 2)
        self.addLink(lb, ids, port1 = 1, port2 = 1)
        self.addLink(ids, sw2, port1 = 2, port2 = 3)
        self.addLink(ids, insp, port1 = 3)
        #zone connnections
        self.addLink(sw1, fw1, port1 = 3, port2 = 1)
        self.addLink(sw2, fw1, port1 = 1, port2 = 2)
        self.addLink(sw2, fw2, port1 = 2, port2 = 1)
        self.addLink(fw2, napt, port1 = 2, port2 = 1)
        self.addLink(napt, sw3, port1 = 2, port2 = 3)

if __name__ == "__main__":

    ctrl = RemoteController('c0', ip = '127.0.0.1', port = 6633)
    topo = MyTopo()

    net = Mininet (
        topo = topo,
        switch = OVSSwitch,
        controller = ctrl,
        autoSetMacs = True,
        autoStaticArp = True
    )

    # add defalut gateway
    net.get("h3").cmd("ip route add default via 10.0.0.1")
    net.get("h4").cmd("ip route add default via 10.0.0.1")

    net.start()

    CLI(net)
