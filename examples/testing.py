# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2020, The University of Memphis,
#                          Arizona Board of Regents,
#                          Regents of the University of California.
#
# This file is part of Mini-NDN.
# See AUTHORS.md for a complete list of Mini-NDN authors and contributors.
#
# Mini-NDN is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Mini-NDN is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Mini-NDN, e.g., in COPYING.md file.
# If not, see <http://www.gnu.org/licenses/>.

import random
import time
import psutil
import os

from mininet.log import setLogLevel, info

from minindn.apps.application import Application

from minindn.helpers.nfdc import Nfdc
from minindn.minindn import Minindn
from minindn.apps.app_manager import AppManager
from minindn.apps.nfd import Nfd
from minindn.util import MiniNDNCLI
from minindn.helpers.ndn_routing_helper import NdnRoutingHelper
from mininet.node import OVSController

from tqdm import tqdm

# ======================= CONFIGURATION ============================
OVERALL_RUN = 4
PUB_TIMING_VALS = [45000]
TIMER_SETTING_VALS = [0]
RUN_NUMBER_VALS = [1]
DROP_RATE_VALS = [50] #[0,25,50]
DELAY_VALS = [10]
TIMER_SCALING_VALS = [3]
LOG_PREFIX = "GEANT37"
TOPO_FILE = "/mini-ndn/examples/geant37.conf" # Update this path as needed

# SVS executable path
SYNC_EXEC = "/mini-ndn/work/ndn-svs/build/examples/core"  # Update this path as needed

# Log directory for SVS
LOG_MAIN_PATH = "/mini-ndn/work/log/{}/".format(OVERALL_RUN)
LOG_MAIN_DIRECTORY = LOG_MAIN_PATH
# ==================================================================

RUN_NUMBER = 0
PUB_TIMING = 0
TIMER_SETTING = 0
DROP_RATE = 0
TIMER_SCALING = 0
DELAY = 0

def getLogPath():
    LOG_NAME = "{}-timer{}-drop{}-scaling{}".format(LOG_PREFIX, TIMER_SETTING, DROP_RATE, TIMER_SCALING)
    logpath = LOG_MAIN_DIRECTORY + LOG_NAME

    if not os.path.exists(logpath):
        os.makedirs(logpath)
        os.makedirs(logpath + '/stdout')
        os.makedirs(logpath + '/stderr')

    return logpath

class SvsCoreApplication(Application):
    """
    Wrapper class to run the SVS core application from each node
    """
    def get_svs_identity(self):
        return "/ndn/{0}-site/{0}/svs_core/{0}".format(self.node.name)

    def start(self):
        exe = SYNC_EXEC
        identity = self.get_svs_identity()

        run_cmd = "{0} {1} {4} {5} {6} >{2}/stdout/{3}.log 2>{2}/stderr/{3}.log &".format(
            exe, identity, getLogPath(), self.node.name, PUB_TIMING, TIMER_SETTING, TIMER_SCALING)

        ret = self.node.cmd(run_cmd)
        info("[{}] running {} == {}\n".format(self.node.name, run_cmd, ret))

def count_running(pids):
    return sum(psutil.pid_exists(pid) for pid in pids)

def get_pids():
    pids = []
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'create_time'])
            if "core" in pinfo['name'].lower():
                pids.append(pinfo['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return pids

if __name__ == '__main__':
    print(LOG_PREFIX, TOPO_FILE, SYNC_EXEC)

    setLogLevel('info')

    Minindn.cleanUp()
    Minindn.verifyDependencies()

    ndn = Minindn(topoFile=TOPO_FILE, controller=OVSController)

    ndn.start()

    info('Starting NFD on nodes\n')
    nfds = AppManager(ndn, ndn.net.hosts, Nfd)
    info('Sleeping 10 seconds\n')
    time.sleep(10)

    info('Setting NFD strategy to multicast on all nodes with prefix')
    for node in tqdm(ndn.net.hosts):
        Nfdc.setStrategy(node, "/ndn/svs", Nfdc.STRATEGY_MULTICAST)

    info('Adding static routes to NFD\n')
    start = int(time.time() * 1000)

    grh = NdnRoutingHelper(ndn.net, 'udp', 'link-state')
    for host in ndn.net.hosts:
        grh.addOrigin([ndn.net[host.name]], ["/ndn/svs/"])

    grh.calculateNPossibleRoutes()

    end = int(time.time() * 1000)
    info('Added static routes to NFD in {} ms\n'.format(end - start))
    info('Sleeping 10 seconds\n')
    time.sleep(10)

    for pub_timing in PUB_TIMING_VALS:
        for run_number in RUN_NUMBER_VALS:
            for timer_setting in TIMER_SETTING_VALS:
                for drop_rate in DROP_RATE_VALS:
                    for timer_scaling in TIMER_SCALING_VALS:
                        for delay in DELAY_VALS:
                            RUN_NUMBER = run_number
                            PUB_TIMING = pub_timing
                            TIMER_SETTING = timer_setting
                            DROP_RATE = drop_rate
                            TIMER_SCALING = timer_scaling
                            DELAY = delay

                            # if TIMER_SETTING == 0 and TIMER_SCALING > 2:
                            #     continue

                            if DROP_RATE == 0 and (TIMER_SETTING > 0 or TIMER_SCALING > 2):
                                continue

                            for link in ndn.net.links:
                                for intf in link.intf1, link.intf2:
                                    intf.config(delay=f'{DELAY}ms', loss=DROP_RATE)

                            for node in ndn.net.hosts:
                                cmd = 'nfdc cs erase /'
                                node.cmd(cmd)

                                with open("{}/report-start-{}.status".format(getLogPath(), node.name), "w") as f:
                                    f.write(node.cmd('nfdc status report'))

                            time.sleep(1)

                            random.seed(RUN_NUMBER)

                            svs_core_app = AppManager(ndn, ndn.net.hosts, SvsCoreApplication)

                            pids = get_pids()
                            info("pids: {}\n".format(pids))
                            count = count_running(pids)
                            while count > 0:
                                info("{} nodes are running\n".format(count))
                                time.sleep(5)
                                count = count_running(pids)

                            for node in ndn.net.hosts:
                                with open("{}/report-end-{}.status".format(getLogPath(), node.name), "w") as f:
                                    f.write(node.cmd('nfdc status report'))

    ndn.stop()

    print(LOG_PREFIX, TOPO_FILE, SYNC_EXEC)