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
HMC mocks
"""

#
# IMPORTS
#
import json
import os
import time

from itertools import cycle
from threading import Thread
from urllib import parse

import yaml

from zhmcclient import Session as ZhmcSession
from zhmcclient_mock import FakedSession, _urihandler as zhmc_urihandler


#
# CONSTANTS AND DEFINITIONS
#
DATA_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    './data')


#
# CODE
#
def datafile(filename: str) -> str:
    """Return path to test data"""
    return os.path.join(DATA_DIR, filename)


# Update GenericGetPropertiesHandler to handle query strings
_original_get_properties = zhmc_urihandler.GenericGetPropertiesHandler.get


def generic_get_properties(method, hmc, uri, uri_parms, logon_required):
    """
    Update GenericGetPropertiesHandler to handle query strings
    """
    uri_split_result = parse.urlsplit(uri)
    query_parms = dict(parse.parse_qsl(uri_split_result.query))
    uri_path = uri_split_result.path
    props = _original_get_properties(
        method, hmc, uri_path, uri_parms, logon_required)
    if requested_props := query_parms.get('properties'):
        return {key: props[key] for key in requested_props.split(',')}
    return props


zhmc_urihandler.GenericGetPropertiesHandler.get = generic_get_properties


class OsMessagesNotificationsMock:
    """Mock for OS Messages notifications receiver"""

    def __init__(self):
        """Constructor"""
        self._notification_type = 'os-message'
        self._notifications = []
        self._cycle = []
        self._yield_count = 2
        self._sequence_number = 999
        self._closed = False

    def close(self):
        """Close stream"""
        self._closed = True

    def notifications(self):
        """Produce notifications received"""
        if self._closed:
            return

        for _ in range(min(self._yield_count, len(self._notifications))):
            yield (
                # header
                {
                    'notification-type': self._notification_type,
                },
                # body
                {
                    'os-messages': [{
                        'sequence-number': self._sequence_number,
                        'message-text': self._notifications.pop(0)
                    }]
                }
            )
            self._sequence_number += 1
        # refill from cycle
        if self._cycle and not self._notifications:
            self._notifications.append(next(self._cycle, None))

    def set_notifications(self, new_notifications: list):
        """Set notifications"""
        self._notifications = new_notifications.copy()

    def set_cycle(self, cycle_items: list):
        """Set cycle"""
        self._cycle = cycle(cycle_items.copy())


class MessagesChannelHandler(zhmc_urihandler.GenericGetPropertiesHandler):
    """
    Messages channel handlers
    """
    AVAILABLE_MESSAGES = []

    @staticmethod
    def get(method, hmc, uri, uri_parms, logon_required):
        """Operation: Get OS messages"""
        uri_split_result = parse.urlsplit(uri)
        query_parms = dict(parse.parse_qsl(uri_split_result.query))
        if begin_sequence_number := query_parms.get('begin-sequence-number'):
            messages = [msg for msg in MessagesChannelHandler.AVAILABLE_MESSAGES
                        if msg['sequence-number'] >= int(begin_sequence_number)]
        else:
            messages = MessagesChannelHandler.AVAILABLE_MESSAGES
        return {'os-messages': messages}

    @staticmethod
    def post(method, hmc, uri, uri_parms, body, logon_required,
             wait_for_completion):
        # pylint: disable=too-many-arguments
        """Operation: Open messages channel."""
        if 'open-os-message-channel' in uri:
            return {'topic-name': 'messages-topic'}
        if 'send-os-cmd' in uri:
            command = body['operating-system-command-text']
            MessagesChannelHandler.AVAILABLE_MESSAGES.append(command)
            if StompConnectionMock.INSTANCE is not None:
                StompConnectionMock.INSTANCE.publish(
                    '', {'notification-type': 'os-message'},
                    json.dumps({'os-messages': [
                        {'sequence-number': int(time.time()),
                            'message-text': command}]}))
        return None


class SessionHandler:
    """
    Handler class for HMC sessions
    """
    STATIC_SESSION = {
        "api-major-version": 20,
        "api-minor-version": 2,
        "api-session": "4hy7c4nogldz4b59ajegzb1dulec641ziyv6uf73zs43205edv",
        "job-notification-topic": "APIUSER.229job",
        "notification-topic": "APIUSER.229",
        "password-expires": 29,
        "session-credential": "un8bu462g37aw9j0o8pltontz3szt35jh4b1qe2toxt6fkhl4"
    }

    @staticmethod
    def post(method, hmc, uri, uri_parms, body, logon_required,
             wait_for_completion):
        # pylint: disable=too-many-arguments
        """Operation: create session"""
        return SessionHandler.STATIC_SESSION

    @staticmethod
    def delete(method, hmc, uri, uri_parms, logon_required):
        # pylint: disable=too-many-arguments
        """Operation: Delete session."""


class SessionMock(FakedSession):
    # pylint: disable=too-many-instance-attributes
    """
    Wraps the FakedSession so that it behaves more like a real mock of the
    Session class.
    """

    def __init__(self, host, userid=None, password=None, session_id=None,
                 get_password=None, retry_timeout_config=None,
                 port=None, verify_cert=True):
        # pylint: disable=too-many-arguments
        """
        Initialize the mock session
        """
        # initialize with custom data
        with open(datafile('hmcclient.yaml'),
                  encoding='utf-8') as hmcclient_file:
            client = yaml.safe_load(hmcclient_file).get(host)

        # initialize FakedSession, arguments are used for FakedHmc
        session_args = (
            client[key]
            for key in ['hmc_host', 'hmc_name', 'hmc_version', 'api_version'])
        super().__init__(*session_args)

        # initialize fields that were skipped by FakedSession
        self._userid = userid
        self._password = password
        self._session_id = session_id
        self._get_password = get_password
        self._retry_timeout_config = ZhmcSession.default_rt_config.override_with(
            retry_timeout_config)
        self._port = port
        self._verify_cert = verify_cert

        # patch the list of uris to include scsi-load
        new_uris = tuple(
            list(zhmc_urihandler.URIS) +
            # add new handlers
            [(r'/api/logical-partitions/([^/]+)/operations/scsi-load',
              zhmc_urihandler.LparLoadHandler),
             (r'/api/partitions/([^/]+)/operations/send-os-cmd',
              MessagesChannelHandler),
             (r'/api/partitions/([^/]+)/operations/open-os-message-channel',
              MessagesChannelHandler),
             (r'/api/partitions/([^/]+)/operations/list-os-messages(?:\?(.*))?',
              MessagesChannelHandler),
             (r'/api/logical-partitions/([^/]+)/operations/send-os-cmd',
              MessagesChannelHandler),
             (r'/api/logical-partitions/([^/]+)/operations/open-os-message-channel',
              MessagesChannelHandler),
             (r'/api/logical-partitions/([^/]+)/operations/list-os-messages(?:\?(.*))?',
              MessagesChannelHandler),
             (r'/api/sessions', SessionHandler),
             (r'/api/sessions/this-session', SessionHandler),
             ]
        )
        self._urihandler = zhmc_urihandler.UriHandler(new_uris)

        SessionHandler.STATIC_SESSION["job-notification-topic"] = self._job_topic
        SessionHandler.STATIC_SESSION["notification-topic"] = self._object_topic
        # self._session_id = 'valid-session-id'

        self._hmc.add_resources({
            'cpcs': client['cpcs'],
            'consoles': client['consoles']
        })


class StompConnectionMock:
    """
    Mock class for stomp.Connection
    """
    INSTANCE = None

    def __init__(self, addr_tuple, use_ssl="SSL"):
        self._addr = addr_tuple
        self._subscriptions = {}
        self._listener = None
        StompConnectionMock.INSTANCE = self

    def connect(self, userid, password, wait=False):
        """
        Connect to the stomp server
        """

    def disconnect(self):
        """
        Disconnect from the stomp server
        """
        # Processing disconnect in test scenarios causes deadlocks

    def subscribe(self, destination, id, ack='auto'):
        #pylint: disable=redefined-builtin,invalid-name
        """
        Subscribe to destination
        """
        self._subscriptions[destination] = id

    def set_listener(self, event, listener):
        """
        Set event listener
        """
        self._listener = listener

    def publish(self, destination, headers, message):
        """
        Send message to destination
        """
        if self._listener and (destination == ''
                               or destination in self._subscriptions):
            self._listener.on_message(headers, message)

    def send_error(self, headers, message):
        """
        Send error message to destination
        """
        if self._listener:
            self._listener.on_error(headers, message)


class StompConnectionTestStream(Thread):
    """Test notifications stream"""

    def __init__(self, test_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        with open(datafile('notifications.yaml'), encoding='utf-8') as jms_file:
            self._items = yaml.safe_load(jms_file)[test_name]
        # update MessagesChannelHandler too
        MessagesChannelHandler.AVAILABLE_MESSAGES = []
        for item in self._items:
            MessagesChannelHandler.AVAILABLE_MESSAGES.extend(
                item['message']['os-messages'])

    def run(self):
        """Run the test stream"""
        for item in self._items:
            time.sleep(item.get('delay', 0))
            StompConnectionMock.INSTANCE.publish(
                '', item['headers'], json.dumps(item['message']))
