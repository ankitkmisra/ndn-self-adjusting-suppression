# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2015-2025, The University of Memphis,
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

import subprocess
from minindn.util import getPopen
from typing import Union, Optional

class Application(object):
    process: subprocess.Popen

    def __init__(self, node):
        self.node = node
        self.process = None
        self.logfile = None
        self.homeDir = self.node.params['params']['homeDir']

        # Make directory for log file
        self.logDir = '{}/log'.format(self.homeDir)
        self.node.cmd('mkdir -p {}'.format(self.logDir))

    def start(self, command: Union[str, list], logfile: Optional[str]=None, envDict: Optional[dict]=None) -> None:
        if self.process is None:
            if isinstance(command, str):
                command = command.split()
            if not logfile:
                self.process = getPopen(self.node, command, envDict)
                return
            self.logfile = open('{}/{}'.format(self.logDir, logfile), 'w')
            self.process = getPopen(self.node, command, envDict,
                                    stdout=self.logfile, stderr=self.logfile)

    def stop(self):
        if self.process is not None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
        if self.logfile is not None:
            self.logfile.close()
