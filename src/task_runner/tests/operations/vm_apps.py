# Copyright 2021 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# pylint:disable=redefined-outer-name,no-self-use,unused-argument

"""
z/VM app mocks
"""

#
# IMPORTS
#


#
# CONSTANTS AND DEFINITIONS
#


#
# CODE
#

from dataclasses import dataclass
import re


@dataclass
class AppResponse:
    """Response from an application running on backend"""
    # output (a list of lines) produced by response
    output: list
    # clear screen before showing output
    clear: bool
    # run state
    displayed_state: str = 'RUNNING'
    # make another app active (can pass start parameters)
    activate: tuple = None


class BaseApp:
    """
    Base application class
    """

    def __init__(self) -> None:
        """Initialize base"""
        self._responses = []
        self._stopped = True

    def _add_response(self, response):
        """Add response to stream"""
        self._responses.append(response)

    def get_response(self):
        """Retrieve a buffered response"""
        if self._responses:
            return self._responses.pop()
        return None

    def drain(self):
        """Retrieve and remove all repsonses"""
        responses = self._responses.copy()
        self._responses.clear()
        return responses


class LogonApp(BaseApp):
    """
    Logon application
    """
    STAGE_LOGON = 1
    STAGE_PASSWORD = 2

    def __init__(self) -> None:
        super().__init__()
        # initial stage
        self._stage = self.STAGE_LOGON
        # asked logon without IPL
        self._noipl = False

    def start(self, *args):
        """Response on app start"""
        self._responses = []
        self._stage = self.STAGE_LOGON
        self._add_response(AppResponse(
            ['z/VM ONLINE', '', 'USERID', 'PASSWORD', 'COMMAND'],
            True,
        ))

    def clear(self):
        """Response on clear action"""
        self._add_response(AppResponse(
            ['Enter one of the following commands',
                '', 'LOGON userid', 'DIAL', 'LOGOFF'],
            True,
        ))

    def input(self, string: str):
        """Process single-line input to this app"""
        cmd = string.lower()
        if self._stage == self.STAGE_PASSWORD:
            self._add_response(AppResponse(
                ['ICH70001I LAST ACCESS AT ...'], False,
                activate=('cp', self._noipl)))

        elif 'logon'.startswith(cmd.strip().split()[0]):
            self._stage = self.STAGE_PASSWORD
            self._noipl = 'noipl' in cmd.split()

            self._add_response(AppResponse(
                [string, '', 'Enter your password,', 'or',
                 'To change your password, enter: ccc/nnn/nnn'],
                False))
        elif cmd.startswith('logoff'):
            self._add_response(AppResponse([string], False))
        else:
            self._add_response(AppResponse(
                [string, ' HCPCFC015E Command not valid before LOGON', ''],
                False))


class CpApp(BaseApp):
    """
    CP application
    """

    def __init__(self) -> None:
        """Init application"""
        super().__init__()
        self._cms = None

    def start(self, no_ipl):
        """Response on app start"""
        self._add_response(AppResponse(
            ['z/VM Version 7 Release 1.0'],
            False,
            displayed_state='CP READ',
            activate=None if no_ipl else ('cms', False)
        ))

    def clear(self):
        """Response on clear action"""
        self._add_response(AppResponse([], True))

    def input(self, string: str):
        """Process single-line input to this app"""
        words = re.findall(r'[#\w]+', string.lower())
        if words[0] != '#cp' and words[0] != 'ipl' and self._cms and self._cms.input(string):
            # processed by CMS
            self._responses.extend(self._cms.drain())
            return
        if words[0] == '#cp':
            words.pop(0)

        if words[0] in 'ipl':
            if words[1] == 'cms':
                self._cms = CmsApp()
                self._cms.start()
                self._responses.extend(self._cms.drain())
            else:
                self._cms = None
                self._add_response(AppResponse(
                    [string, 'IPL performed'], False))
            return
        if words[0] == 'logoff':
            self._add_response(AppResponse(['LOGOFF AT 20:20:20', ''],
                                           False, displayed_state='CP READ'))
            return
        if words[0] in 'disconnect':
            self._add_response(AppResponse(['DISCONNECT AT 20:20:20', ''],
                                           False, displayed_state='CP READ'))
            return
        if words[0] == 'sys' and words[1] == 'clear':
            self._add_response(AppResponse(['Storage cleared - system reset'],
                                           False, displayed_state='CP READ'))
            return

        self._add_response(AppResponse(['00: ' + string, '00: CP'],
                                       False, displayed_state='CP READ'))


class CmsApp(BaseApp):
    """
    CMS application
    """
    STAGE_INIT = 1
    STAGE_ACTIVE = 2

    def __init__(self) -> None:
        super().__init__()

        self._stage = self.STAGE_INIT

    def start(self):
        """Response on app start"""
        self._stage = self.STAGE_INIT
        self._add_response(AppResponse(
            ['z/VM V7.1.0'],
            False,
            displayed_state='VM READ',
        ))

    def input(self, string: str):
        """
        Process single-line input to this app

        This method returns False if a command is not processed,
        so that it could be handled by CP
        """
        if self._stage == self.STAGE_INIT:
            self._stage = self.STAGE_ACTIVE
            words = re.findall(r'\w+', string.lower())
            no_profile = (
                len(words) >= 2
                and words[0] in 'access' and words[1] in 'noprofile')

            self._add_response(AppResponse([
                string,
                '' if no_profile else 'PROFILE EXEC RUNNING',
                'Ready; T=0.01/0.01'], False))
            return True

        # active stage: regular commands
        self._add_response(AppResponse([
            string,
            'Ready; T=0.01/0.01'], False))
        return True
