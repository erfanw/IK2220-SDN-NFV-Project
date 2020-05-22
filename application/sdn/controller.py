
from pox.core import core
import pox.openflow.libopenflow_01 as of
import time
from forwarding.l2_learning import LearningSwitch
from pbz_firewall import pbz_firewall
from prz_firewall import prz_firewall
import subprocess
import shlex

log = core.getLogger()

class controller (object) :

    def __init__(self, transparent):

        core.openflow.addListeners(self)
        self.transparent = transparent

    def _handle_ConnectionUp(self, event):

        log.debug("event from %s" % (event.dpid))

        if event.dpid == 5:
            log.debug("firewall_1 is launched!")
            pbz_firewall(event.connection)

        elif event.dpid == 6:
            log.debug("firewall_2 is launched!")
            prz_firewall(event.connection)

        elif event.dpid == 7 :
            log.debug("napt is connected")
            args = "sudo /usr/local/bin/click -f /home/click/ik2220-assign-phase2-team4/application/nfv/napt.click"
            subprocess.Popen(shlex.split(args))

        elif event.dpid == 8 :
            log.debug("lb is connected")
            args = "sudo /usr/local/bin/click -f /home/click/ik2220-assign-phase2-team4/application/nfv/lb.click"
            subprocess.Popen(shlex.split(args))

        elif event.dpid == 9 :
            log.debug("ids is connected")
            args = "sudo /usr/local/bin/click -f /home/click/ik2220-assign-phase2-team4/application/nfv/ids.click"
            subprocess.Popen(shlex.split(args))

        else :
            log.debug("connection %s" % (event.connection, ))
            LearningSwitch(event.connection, self.transparent)

def launch() :
    core.registerNew(controller, False)

