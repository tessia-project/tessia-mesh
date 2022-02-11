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
Wrapper tests
"""

#
# IMPORTS
#

import re
import pytest

from task_runner.machines.operations import zvm
from task_runner.machines.operations.s3270 import wrapper

from .vm_mocks import TerminalMock

#
# CONSTANTS AND DEFINITIONS
#


#
# CODE
#


@pytest.fixture
def mock_connection(monkeypatch):
    """Substitute Pipe connector with our custom class"""
    monkeypatch.setattr(zvm, 'S3270PipeConnector', TerminalMock)


def test_changed_rows_are_correctly_reported():
    """Changed rows correctness test"""
    screen = ['DATA 1', 'DATA 2', '      ', '      ']
    chset1 = ['DATA 1', 'DATA 2', 'DATA 3', '      ']
    chset2 = ['DATA 1', 'DATA 2', 'DATA 3', 'DATA 4']
    chset3 = ['      ', '      ', 'DATA 5', '      ']
    chset4 = ['DATA 1', 'DATA 2', '      ', '      ', 'DATA 5', 'DATA 6']
    change1 = wrapper.get_changed_rows(screen, chset1)
    change2 = wrapper.get_changed_rows(screen, chset2)
    change3 = wrapper.get_changed_rows(screen, chset3)
    change4 = wrapper.get_changed_rows(screen, chset4)
    assert change1 == chset1[2:3]
    assert change2 == chset2[2:4]
    assert change3 == chset3[0:3]
    assert change4 == chset4[4:6]
    assert wrapper.get_changed_rows(screen, screen) == []


def test_screen_wrapper_is_operational():
    """
    Test screen wrapper with a mock connection
    """
    conn = TerminalMock()
    terminal = wrapper.ScreenWrapper(conn)
    area = (1, 1, -2, 0)

    terminal.send('Connect(vmhost)')
    output_stream = terminal.output_stream(timeout=0.5, area=area)
    screen = list(map(str.strip, next(output_stream)))

    assert 'z/VM ONLINE' in screen
    assert 'COMMAND' in screen
    # no more output
    with pytest.raises(StopIteration):
        next(output_stream)

    # Clear on logon screen replaces logo with a clean logon text prompt
    terminal.send('Clear')

    # Use an artificial exception to mark that a line was found,
    # because otherwise the assertion might not execute
    with pytest.raises(StopIteration):
        # this is the expected use of output_stream method
        for lines in terminal.output_stream(timeout=1.0, area=area):
            if 'LOGON userid' in map(str.strip, lines):
                raise StopIteration

    terminal.send('String("logon vm1 here")')
    terminal.send('Enter')
    with pytest.raises(StopIteration):
        # this is the expected use of output_stream method
        for lines in terminal.output_stream(timeout=4.0, area=area):
            if any('Enter your password' in line.strip() for line in lines):
                raise StopIteration

    terminal.send('Disconnect')


def test_zvm_script_performs_logon(mock_connection):
    """Logon with a script for z/VM session"""
    hyp = zvm.ZvmHypervisor('zvm.example.com', {})
    session = zvm.ZvmSession(hyp)
    script = [
        {'command': 'Clear',
         'match': {'re': re.compile('LOGON userid')}},
        {'command': 'String("logon {host} here noipl\n")',
         'match': {'re': re.compile('Enter your password')}},
        {'command': 'String("example\n")',
         'match': {'re': re.compile('z/VM Version 7 Release')}},
        {'command': 'Clear'},
        {'command': 'String("ipl cms\n")',
         'match': {'re': re.compile('z/VM V7.1.0')}},
        {'command': 'String("acc (noprof\n")',
         'match': {'re': re.compile('Ready;'),
                   'stop': 'ok'}},
    ]
    args = {'host': 'vm1'}
    behaviour = {'command_timeout': 4.0}

    session.connect()
    result = session.run_script(script, args, behaviour)
    session.disconnect()

    assert result == 'ok'


def test_zvm_script_logon_failed(mock_connection):
    """Logon with a script for z/VM session"""
    hyp = zvm.ZvmHypervisor('zvm.example.com', {})
    session = zvm.ZvmSession(hyp)
    script = [
        {'command': 'Clear',
         'match': {'re': re.compile('LOGON userid')}},
        {'command': 'String("invalid command\n")',
         'match': {'re': re.compile('Enter your password'),
                   'stop': 'ok'}},
    ]
    args = {'host': 'vm1'}
    behaviour = {
        'command_timeout': 4.0,
        'errors': [re.compile('HCPCFC015E')]
    }

    session.connect()
    with pytest.raises(RuntimeError, match=behaviour['errors'][0]):
        session.run_script(script, args, behaviour)
    session.disconnect()


def test_zvm_logon(mock_connection):
    """Logon with a script for z/VM session"""
    hyp = zvm.ZvmHypervisor('zvm.example.com', {})
    session = zvm.ZvmSession(hyp)

    session.connect()
    result = session.logon({'guest_name': 'vm1', 'password': 'example'})
    session.disconnect()

    assert result == 'ok'
