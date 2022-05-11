# Copyright 2022 IBM Corp.
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
Test HMC Notifications
"""

#
# IMPORTS
#

import pytest

from task_runner.machines.operations import hmc

from .hmc_mocks import OsMessagesNotificationsMock, \
    SessionMock, StompConnectionMock, StompConnectionTestStream

#
# CONSTANTS AND DEFINITIONS
#


#
# CODE
#


@pytest.fixture
def mock_session(monkeypatch):
    """Substitute HMC Session"""
    monkeypatch.setattr(hmc.zhmcclient, 'Session', SessionMock)
    monkeypatch.setattr('stomp.Connection', StompConnectionMock)

@pytest.fixture
def hypervisor() -> hmc.CpcHypervisor:
    """Create hypervisor definition"""
    return hmc.CpcHypervisor(
        'hmc.example.com', {'username': 'user', 'password': 'password'},
        {'verify_certificate': False})


@pytest.fixture
def guest() -> hmc.CpcPartition:
    """Create guest definition"""
    return hmc.CpcPartition('CPC1', 'lp1')


@pytest.fixture
def hmc_session(mock_session, hypervisor):
    """Create a faked session with static data"""
    session = hmc.HmcSession(hypervisor)
    session.connect()
    yield session
    session.disconnect()


def test_jms_notifications_are_received():
    """Test that OS Messages notifications can be read"""
    src_messages = ['Msg 1', 'Msg 2', 'Msg 3']
    src_cycle = ['Several', 'lines', 'of', 'text']
    dst_messages = []
    dst_cycle = []
    mock_source = OsMessagesNotificationsMock()
    mock_source.set_notifications(src_messages)
    mock_source.set_cycle(src_cycle)
    with hmc.HmcNotifications(lambda: mock_source) as notifications:
        while len(dst_messages) < len(src_messages):
            msg = notifications.get_notification(0.5)
            dst_messages.append(
                msg['message']['os-messages'][0]['message-text'])
        while len(dst_cycle) < len(src_cycle) * 2:
            msg = notifications.get_notification(0.5)
            dst_cycle.append(
                msg['message']['os-messages'][0]['message-text'])
    assert dst_messages == src_messages
    assert dst_cycle == src_cycle * 2


def test_console_stream_forward_sequence_is_read(hmc_session, guest):
    """
    Test HMC console stream is read when message IDs are sequential
    """
    read_msg = []
    with hmc.HmcConsoleStream(hmc_session, guest) as stream:
        test_data = StompConnectionTestStream('console_stream_forward')
        test_data.start()
        while items := stream.read(timeout=2.):
            read_msg.extend(items)
        stream.write('Command')
        read_msg.extend(stream.read(timeout=2.))
        test_data.join()

    # see notifications.yaml
    assert len(read_msg) == 4 + 1
    assert read_msg[-1] == 'Command'
