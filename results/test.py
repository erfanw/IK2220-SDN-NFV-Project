
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import OVSSwitch
from mininet.node import RemoteController
import os
import time

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


    # #test

    pingCount = 0
    pingCorrect = 0
    tcpCount = 0
    tcpCorrect = 0
    httpCount = 0
    httpCorrect = 0



    def ping_test_1(client, server, str1, str2):
        print('Sending ICMP request from ' + str1 + ' to ' + str2 + '...')
        report.write('ICMP test from %s to %s:\n' %(str1, str2))
        pingTest = client.cmd('ping %s -c 1 -w 1'%server.IP())
        global pingCount
        global pingCorrect
        if pingTest.find('1 received') > -1:
            report.write('Response received. This is correct.\n')
            pingCount += 1
            pingCorrect += 1
        else:
            report.write('Response not received. This is wrong.\n')
            pingCount += 1


    def ping_test_2(client, server, str1, str2):
        print('Sending ICMP request from ' + str1 + ' to ' + str2 + '...' )
        report.write('ICMP test from %s to %s:\n' %(str1, str2))
        pingTest = client.cmd('ping %s -c 1 -w 1'%server.IP())
        global pingCount
        global pingCorrect
        if pingTest.find('1 received\n') > -1:
            report.write('Response received. This is wrong.\n')
            pingCount += 1
        else:
            report.write('Response not received. This is correct.\n')
            pingCount += 1
            pingCorrect += 1

    def ping_test_3(client, str1, str2):
        print('Sending ICMP request from ' + str1 + ' to lb ...')
        report.write('ICMP test form %s to lb:\n' %str1)
        pingTest = client.cmd('ping 100.0.0.45 -c 1 -w 1')
        global pingCount
        global pingCorrect
        if pingTest.find('1 received') > -1:
            report.write('Response received. This is correct.\n')
            pingCount += 1
            pingCorrect += 1
        else:
            report.write('Response not received. This is wrong.\n')
            pingCount += 1

    def tcp_test_1(client, server, str1, str2, port):
        print('TCP connnection test from %s to %s, port %s' %(str1, str2, port))
        report.write('TCP connnection test from %s to %s, port %s\n' %(str1, str2, port))
        server.cmd('nc -l -p %s &' %port)
        tcpTest = client.cmd('nc -vz -w 1 %s %s' %(server.IP(), port))
        global tcpCount
        global tcpCorrect
        if tcpTest.find('succeed') > -1:
            report.write('Connection succeeded. This is correct\n')
            tcpCount += 1
            tcpCorrect += 1
        else:
            report.write('Connection timed out. This is wrong\n')
	    tcpCount += 1


    def tcp_test_2(client, server, str1, str2, port):
        print('TCP connnection test from %s to %s, port %s' %(str1, str2, port))
        report.write('TCP connnection test from %s to %s, port %s\n' %(str1, str2, port))
        server.cmd('nc -l -p %s &' %port)
        tcpTest = client.cmd('nc -vz -w 1 %s %s' %(server.IP(), port))
        global tcpCount
        global tcpCorrect
        if tcpTest.find('succeed') > -1:
            report.write('Connection succeeded. This is wrong.\n')
            tcpCount += 1
        else:
            report.write('Connection timed out. This is correct.\n')
	    tcpCount += 1
	    tcpCorrect += 1

    def tcp_test_3(client, server, str1, str2, port):
        print('TCP connnection test from %s to %s, port %s' %(str1, str2, port))
        report.write('TCP connnection test from %s to %s, port %s\n' %(str1, str2, port))
        server.cmd('nc -l -p %s &' %port)
        tcpTest = client.cmd('nc -vz -w 1 %s %s' %('100.0.0.45', port))
        global tcpCount
        global tcpCorrect
        if tcpTest.find('succeed') > -1:
            report.write('Connection succeeded. This is correct.\n')
            tcpCount += 1
            tcpCorrect += 1
        else:
            report.write('Connection timed out. This is wrong.\n')
            tcpCount += 1

    def tcp_test_4(client, server, str1, str2, port):
        print('TCP connnection test from %s to %s, port %s' %(str1, str2, port))
        report.write('TCP connnection test from %s to %s, port %s\n' %(str1, str2, port))
        server.cmd('nc -l -p %s &' %port)
        tcpTest = client.cmd('nc -vz -w 1 %s %s' %('100.0.0.45', port))
        global tcpCount
        global tcpCorrect
        if tcpTest.find('succeed') > -1:
            report.write('Connection succeeded. This is wrong.\n')
            tcpCount += 1
        else:
            report.write('Connection timed out. This is correct.\n')
            tcpCount += 1
            tcpCorrect += 1

    def http_test_1(client, method):
	print('HTTP test with %s method' %(method))
	httpTest = client.cmd('curl 100.0.0.45 -m1 -s -X %s' %(method))
	global httpCount
	global httpCorrect
	if httpTest.find('Server') > -1:
	    report.write('HTTP %s request sent to servers. This is correct.\n' %(method))
	    httpCount +=1
   	    httpCorrect += 1
	else:
	    report.write('HTTP %s request sent to inspector. This is wrong.\n' %(method))
	    httpCount += 1
	#time.sleep(1)

    def http_test_2(client, method):
        print('HTTP test with %s method' %(method))
	httpTest = client.cmd('curl 100.0.0.45 -m1 -s -X %s' %(method))
        global httpCount
        global httpCorrect
	if httpTest.find('Server') > -1:
            report.write('HTTP %s request sent to servers. This is wrong.\n' %(method))
            httpCount += 1
	else:
            report.write('HTTP %s request sent to inspector. This is correct.\n' %(method))
	    httpCount += 1
            httpCorrect += 1

    path = "/home/click/ik2220-assign-phase2-team4/results/phase_2_report"
    reportPath = os.path.expanduser(path)
    report = open(reportPath, 'w')
    report.truncate()

    print('Tests begin. Please Wait...\n')

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')

    ws1 = net.get('ws1')
    ws2 = net.get('ws2')
    ws3 = net.get('ws3')
    insp = net.get('insp')
    lb = net.get('lb')

    insp.cmd('tcpdump &')
    print('inspector dumping on eth1\n')
    report.write('IK2220-assign-phase2-team4 Test Report\n\n')
    report.write('Results for ICMP tests:\n')
    print('ICMP test begins:')

    ping_test_3(h1, 'PbZ', 'LB')
    ping_test_3(h2, 'PbZ', 'LB')
    ping_test_3(h3, 'PrZ', 'LB')
    ping_test_3(h4, 'PrZ', 'LB')
    ping_test_1(h1, h2, 'PbZ', 'PbZ')
    ping_test_2(h1, h3, 'PbZ', 'PrZ')
    ping_test_2(h1, ws1, 'PbZ', 'Web Server')
    ping_test_1(h3, h4, 'PrZ', 'PrZ')
    ping_test_1(h3, h1, 'PrZ', 'PbZ')
    ping_test_2(h3, ws1, 'PrZ', 'Web Server')


    pingRate = float(pingCorrect) / float(pingCount)
    print('Number of correct case: %d, total case: %d' %(pingCorrect, pingCount))
    pingCorrectRate = '%.2f%%' % (pingRate * 100)
    report.write('\nICMP test success rate is %s' %pingCorrectRate)

    time.sleep(2)
    print('\n\n\n\nTCP tests begins:')
    report.write('\n\n\n\nResults for TCP tests:\nRule: hosts in PbZ cannot initiate TCP connection to any hosts in PrZ. Hosts in PrZ can initiate TCP connection to hosts in PbZ with any dstport. Hosts in both PbZ and PrZ can only initiate TCP connections to lb with dstport 80 and web servers will respond in a round robin way.\n\n')


    tcp_test_3(h1, ws1, 'PbZ', 'DMZ', '80')
    tcp_test_3(h1, ws2, 'PbZ', 'DMZ', '80')
    tcp_test_3(h1, ws3, 'PbZ', 'DMZ', '80')
    tcp_test_3(h3, ws1, 'PrZ', 'DMZ', '80')
    tcp_test_4(h3, ws1, 'PrZ', 'DMZ', '80')
    tcp_test_3(h3, ws3, 'PrZ', 'DMZ', '80')
    tcp_test_3(h2, ws1, 'PbZ', 'DMZ', '80')
    tcp_test_3(h2, ws2, 'PbZ', 'DMZ', '80')
    tcp_test_4(h2, ws2, 'PbZ', 'DMZ', '80')
    tcp_test_4(h1, ws3, 'PbZ', 'DMZ', '122')
    tcp_test_4(h3, ws3, 'PrZ', 'DMZ', '84')
    tcp_test_2(h1, h3, 'PbZ', 'PrZ', '81')
    tcp_test_2(h1, h3, 'PbZ', 'PrZ', '80')
    tcp_test_2(h1, h3, 'PbZ', 'PrZ', '1942')
    tcp_test_1(h3, h1, 'PrZ', 'PbZ', '1453')
    tcp_test_1(h3, h1, 'PrZ', 'PbZ', '80')
    tcp_test_1(h3, h1, 'PrZ', 'PbZ', '514')


    tcpRate = float(tcpCorrect) / float(tcpCount)
    print('Number of correct case: %d, total case: %d' %(tcpCorrect, tcpCount))
    tcpCorrectRate = '%.2f%%' % (tcpRate * 100)
    report.write('\nTcp test success rate is %s' %tcpCorrectRate)


    print('\n\n\nHTTP Test Begins')

    report.write('\n\n\nResult for HTTP tests:\n')

    ws1.cmd('python -m SimpleHTTPServer 80 &')
    ws2.cmd('python -m SimpleHTTPServer 80 &')
    ws3.cmd('python -m SimpleHTTPServer 80 &')
    time.sleep(1)

    print('\nTesting HTTP methods...\n')
    http_test_1(h1, 'POST')
    http_test_2(h1, 'GET')
    http_test_2(h1, 'TRACE')
    http_test_2(h1, 'DELETE')
    http_test_2(h1, 'HEAD')
    http_test_2(h1, 'CONNECT')
    http_test_2(h1, 'OPTIONS')
    
    print('\nTesting HTTP PUT injections...\n')

    http_test_2(h3, 'PUT --data "cat /etc/passwd"')
    http_test_2(h3, 'PUT --data "INSERT"')
    http_test_2(h3, 'PUT --data "cat /var/log"')
    http_test_2(h3, 'PUT --data "UPDATE"')
    http_test_2(h3, 'PUT --data "DELETE"')

    print('Number of correct case: %d, total case: %d' %(httpCorrect, httpCount))

    httpRate = float(httpCorrect) / float(httpCount)
    httpCorrectRate = '%.2f%%' % (httpRate * 100)
    report.write('\nHTTP test success rate is %s' %httpCorrectRate)


    totalCorrect = pingCorrect + tcpCorrect + httpCorrect
    totalCount = pingCount + tcpCount + httpCount
    print('\nNumber of total correct case: %d, total case: %d' %(totalCorrect, totalCount))
    totalCorrectRate = '%.2f%%' % ((float(totalCorrect)/float(totalCount)) * 100)
    report.write('\n\nTotal success rate is %s' %totalCorrectRate)


    print('\nTest completed! Please refer to "phase_2_report" for results')
    report.write('\n\nTest completed!\n')

    os.system('sudo killall click')
    os.system('sudo killall python2.7')

    net.stop()
