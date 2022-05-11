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

"""
Hypoervisor session

Keeps a session to the hypervisor for reuse
"""


#
# IMPORTS
#
from datetime import datetime, timedelta, timezone
from enum import Enum
import itertools
import logging
import sys
import threading

from dataclasses import dataclass
from queue import Empty, Queue, SimpleQueue
from threading import Thread
from urllib.parse import urlsplit

import zhmcclient

from .hypconsole import HypStream

#
# CONSTANTS AND DEFINITIONS
#
DEFAULT_CONNECTION_OPTIONS = {
    'port': zhmcclient.DEFAULT_HMC_PORT,
    'stomp_port': zhmcclient.DEFAULT_STOMP_PORT,
    'connect_timeout': zhmcclient.DEFAULT_CONNECT_TIMEOUT,
    'status_timeout': zhmcclient.DEFAULT_STATUS_TIMEOUT,
    'operation_timeout': zhmcclient.DEFAULT_OPERATION_TIMEOUT,
    'verify_certificate': True
}


# Notification buffer size
# Queue accumulates messages from NotificationReceiver and blocks when
# length is exceeded.
# Each queue entry is not a single message, but a chunk of several messages,
# as received by NotificationReceiver.
# The exact value is therefore somewhat arbitrary chosen, but value of 1 will
# serialize processing/waiting loop
MAX_QUEUED_NOTIFICATIONS = 20

# Maximum number of messages read from queue
# Prevents list of returned messages from growing indefinitely
MAX_RETURNED_MESSAGES_PER_CALL = 100


TZINFO = timezone.utc
#
# CODE
#
logger = logging.getLogger(__name__)


@dataclass
class CpcHypervisor:
    """HMC hypervisor definition"""
    hostname: str
    credentials: dict
    connection_options: dict

    def __repr__(self) -> str:
        return f'CpcHypervisor({self.hostname})'
# CpcHypervisor


@dataclass
class CpcPartition:
    """A complex name for a partition"""
    cpc: str
    partition_name: str

    def __repr__(self) -> str:
        return f'CpcPartition({self.cpc}, {self.partition_name})'
# CpcPartition


class HmcNotificationMessageType(Enum):
    """
    Notification message types

    Value corresponds to value set in JMS message header
    (see HMC Web Services API)
    """
    OS_MESSAGE = 'os-message'
    STATUS_CHANGE = 'status-change'
    PROPERTY_CHANGE = 'property-change'
    INVENTORY_CHANGE = 'inventory-change'
    JOB_COMPLETION = 'job-completion'
    LOG_ENTRY = 'log-entry'
# HmcNotificationMessageType


class HmcNotificationTopic(Enum):
    """
    Notification topics

    Value corresponds to topic types returned by get_notification_topics
    (see HMC Web Services API)
    """
    OBJECT_TOPIC = 'object-notification'
    JOB_TOPIC = 'job-notification'
    AUDIT_TOPIC = 'audit-notification'
    SECURITY_TOPIC = 'security-notification'
    OS_MESSAGE_TOPIC = 'os-message-notification'
# HmcNotificationTopic


class HmcSession:
    """HMC hypervisor session"""

    def __init__(self, hypervisor: CpcHypervisor) -> None:
        """Initialize hypervisosr"""
        self._hypervisor = hypervisor
        self._connection_options = DEFAULT_CONNECTION_OPTIONS.copy()
        self._connection_options.update(hypervisor.connection_options)

        self._client = None
        self._cache = {}
    # __init__()

    def _find_guest(self, guest: CpcPartition) -> "union[zhmcclient.Partition,zhmcclient.Lpar]":
        """Find and cache guest object"""
        # check cache
        if partition := self.cache(guest.partition_name):
            return partition

        # find CPC
        cpc: zhmcclient.Cpc = self._client.cpcs.find_by_name(guest.cpc)
        if not cpc:
            raise RuntimeError(f"CPC {guest.cpc} not found")

        # query and cache only interesting properties
        # direct query considerably saves request time
        cpc_props = self._client.session.get(
            f'{cpc.uri}?properties=dpm-enabled')
        if 'dpm-enabled' not in cpc_props:
            cpc_props['dpm-enabled'] = False
        cpc.update_properties_local(cpc_props)

        # find guest
        if cpc.dpm_enabled:
            partition = cpc.partitions.find_by_name(guest.partition_name)
        else:
            partition = cpc.lpars.find_by_name(guest.partition_name)
        if not partition:
            logger.debug("Partition %s on CPC %s not found",
                         guest.partition_name, guest.cpc)
            logger.debug("CPC %s status: %s", guest.cpc, cpc.prop('status'))
            raise RuntimeError("Partition not found")

        # get current partition status
        self._refresh_partition_properties(partition)

        # cache and return
        return self.cache(guest.partition_name, partition)
    # _find_guest()

    def _find_storage_volume(self, guest: CpcPartition, boot_params):
        """
        Find the uri of a storage volume
        """
        partition = self._find_guest(guest)
        if boot_params['volume_type'] == 'fcp':
            sg_type = 'fcp'
            prop_key = 'uuid'
            prop_value = boot_params['uuid']
        elif boot_params['volume_type'] == 'dasd':
            sg_type = 'fc'
            prop_key = 'device-number'
            prop_value = boot_params['volume_id']

        logger.debug("Looking for storage volume object with %s='%s'",
                     prop_key, prop_value)
        # search the corresponding volume in the storage groups attached to the
        # partition
        for sg_uri in partition.get_property('storage-group-uris'):
            sg_obj = self._client.consoles.console.\
                storage_groups.resource_object(sg_uri)
            if sg_obj.get_property('type').lower() != sg_type:
                logger.debug(
                    "Skipping storage group %s, type '%s' (actual) != '%s' "
                    "(expected)", sg_obj.get_property('name'),
                    sg_obj.get_property('type').lower(), sg_type)
                continue
            # find the matching volume
            for sg_vol in sg_obj.storage_volumes.list():
                sg_vol.pull_full_properties()
                try:
                    sg_vol_value = sg_vol.get_property(prop_key)
                except KeyError:
                    continue
                if sg_vol_value.lower() != prop_value.lower():
                    continue
                if sg_vol.get_property('usage') != 'boot':
                    sg_vol.update_properties({'usage': 'boot'})
                return sg_vol.get_property('element-uri')

        raise ValueError(
            f'Storage volume <{prop_key}:{prop_value}> not found'
            ' or not attached to partition')
    # _find_storage_volume()

    def cache(self, key, value=None):
        """Retrieve or store a session object"""
        if value is None:
            return self._cache.get(key, None)
        self._cache[key] = value
        return value
    # cache()

    def compatible(self, other_hypervisor) -> bool:
        """Test if hypervisor definitions are similar"""
        return (isinstance(other_hypervisor, CpcHypervisor)
                and other_hypervisor == self._hypervisor)
    # compatible()

    def connect(self):
        """Connect to HMC"""
        logger.info("Connecting to HMC %s", self._hypervisor.hostname)
        rt_config = zhmcclient.RetryTimeoutConfig(
            connect_timeout=self._connection_options['connect_timeout'],
            operation_timeout=self._connection_options['operation_timeout'],
            status_timeout=self._connection_options['status_timeout'],
        )
        session = zhmcclient.Session(
            self._hypervisor.hostname,
            self._hypervisor.credentials['username'],
            self._hypervisor.credentials['password'],
            retry_timeout_config=rt_config,
            port=self._connection_options['port'],
            verify_cert=self._connection_options['verify_certificate'])

        try:
            session.logon()
        except zhmcclient.ServerAuthError as exc:
            raise RuntimeError(
                f'HMC login failed: {exc.details.message}') from exc

        if audit_id := self._hypervisor.credentials.get('audit-id'):
            session.headers['X-Audit-Id'] = audit_id
        self._client = zhmcclient.Client(session)
        self._cache.clear()
    # connect()

    @property
    def connected(self) -> bool:
        """Test if connected to HMC"""
        return self._client is not None and self._client.session.is_logon()
    # connected()

    @staticmethod
    def _normalize_address(address):
        """
        Convert the load address to the format expected by the HMC API.

        Args:
            address (str): string in the format 0.0.1500 or 1500

        Returns:
            str: normalized load address
        """
        return address.replace('.', '')[-5:]
    # _normalize_address()

    def _refresh_partition_properties(self, partition, properties=('status',)):
        """Refresh partition properties from HMC"""
        if properties is None:
            partition.pull_full_properties()
        else:
            partition_props = self._client.session.get(
                f'{partition.uri}?properties={",".join(properties)}')
            partition.update_properties_local(partition_props)
    # _refresh_partition_properties

    def deactivate(self, guest: CpcPartition):
        """Stop a guest"""
        partition = self._find_guest(guest)
        logger.info("Deactivating partition %s", guest.partition_name)

        if partition.manager.cpc.dpm_enabled:
            logger.info("DPM deactivation is not required")
            return

        partition.deactivate()
    # stop()

    def disconnect(self):
        """Disconnect from HMC"""
        if self._client:
            logger.info("Disconnecting from HMC %s", self._hypervisor.hostname)
            self._cache.clear()
            self._client.session.logoff()
            self._client = None
    # disconnect()

    def get_notification_topic(self, notification_topic: HmcNotificationTopic,
                               guest: CpcPartition = None) -> str:
        """
        Get the requested topic

        Raises:
            zhmcclient.HTTPError: generic HTTP error
            RuntimeError: requested topic is not found
        """
        if notification_topic == HmcNotificationTopic.JOB_TOPIC:
            return self._client.session.job_topic
        if notification_topic == HmcNotificationTopic.OBJECT_TOPIC:
            return self._client.session.object_topic
        if notification_topic == HmcNotificationTopic.OS_MESSAGE_TOPIC:
            # messages are created ad hoc, but may raise exceptions
            try:
                guest_obj = self._find_guest(guest)
                return guest_obj.open_os_message_channel(
                    include_refresh_messages=True)
            except zhmcclient.HTTPError as exc:
                # 409,331: topic already exists for the current partition,
                # we have a fallback case for that.
                # Otherwise raise the original exception
                if not (exc.http_status == 409 and exc.reason == 331):
                    raise

        all_topics = self._client.session.get_notification_topics()
        # From all the topics returned we only need those that are
        # related to os-message-notification AND have the desired
        # LPAR object specified
        # LPAR object has its unique ID, and we search for it
        # in the 'object-uri' field (comparing this directly is
        # not robust enough)
        matching_topics = [
            topic['topic-name'] for topic in all_topics
            if topic['topic-type'] == notification_topic.value and
            (notification_topic != HmcNotificationTopic.OS_MESSAGE_TOPIC or
             topic['object-uri'].split('/')[-1] == guest_obj.uri.split('/')[-1]
             )]
        if not matching_topics:
            # none found - that is very much an error
            logger.debug(
                'No matching topic %s found in %s',
                notification_topic, all_topics)
            raise RuntimeError(
                'Requested notification topic does not exist') from None

        if len(matching_topics) > 1:
            # make a note, but can probably work
            logger.debug('Multiple topic entries %s found in %s',
                         notification_topic, all_topics)

        return matching_topics[0]
    # get_notification_topic()

    def get_os_messages(self, guest: CpcPartition,
                        begin_seq_nr: int = 0) -> list:
        """
        Get the list of OS messages for a guest

        Args:
            guest (CpcPartition): guest partition
            begin_seq_nr (int): message sequence number to start from

        Returns:
            list: list of OS messages
        """
        guest_obj = self._find_guest(guest)
        # at the moment of writing zhmcclient did not have a method
        # to get the list of OS messages, so we'll issue a direct URL request
        try:
            os_messages_resp = self._client.session.get(
                f'{guest_obj.uri}/operations/list-os-messages'
                f'?begin-sequence-number={begin_seq_nr}')
        except zhmcclient.ParseError as exc:
            logger.debug("get_os_messages failed: %s", exc)
            return []

        os_messages = os_messages_resp['os-messages']
        return os_messages
    # get_os_messages()

    def open_notification_receiver(self, topic: str):
        """
        Return a notification receiver object
        """
        return zhmcclient.NotificationReceiver(
            topic,
            self._hypervisor.hostname,
            self._hypervisor.credentials['username'],
            self._hypervisor.credentials['password'],
            port=self._connection_options['stomp_port'])
    # open_notification_receiver()

    def send_os_command(self, command: str, guest: CpcPartition):
        """Send command to OS"""
        logger.debug("Sending command to OS: %s", command)
        partition = self._find_guest(guest)
        partition.send_os_command(command)
    # send_os_message()

    def set_dpm_boot_params(self, guest: CpcPartition, boot_params: dict):
        """Set boot parameters in DPM mode"""
        if boot_params['boot_method'] == 'ftp':
            parsed_url = urlsplit(boot_params['uri'])
            update_props = {
                'boot-device': 'ftp',
                'boot-ftp-host': parsed_url.hostname,
                'boot-ftp-username': parsed_url.username or 'anonymous',
                'boot-ftp-password': parsed_url.password or 'anonymous',
                'boot-ftp-insfile': parsed_url.path,
            }
            self.update_properties(guest, update_props)
        elif boot_params['boot_method'] == 'volume':
            # this boot method requires DPM storage management feature
            cpc = self._client.cpcs.find_by_name(guest.cpc)
            try:
                is_dpm_storage = cpc.feature_enabled('dpm-storage-management')
            except ValueError as exc:
                logger.debug("CPC dpm-storage-management feature query: %s",
                             exc)
                is_dpm_storage = False

            if not is_dpm_storage:
                raise RuntimeError("DPM storage management is not enabled")

            svol_uri = self._find_storage_volume(guest, boot_params)
            update_props = {
                'boot-device': 'storage-volume',
                'boot-storage-volume': svol_uri,
            }
            if boot_params.get('secure_boot', False):
                update_props['secure-boot'] = True

            self.update_properties(guest, update_props)
        elif boot_params['boot_method'] == 'custom':
            # pass through the props
            update_props = {key: value for key, value in boot_params.items()
                            if key.startswith('boot-') or key == 'secure-boot'}
            self.update_properties(guest, update_props)

        else:
            logger.warning("Unknown boot_method %s",
                           boot_params['boot_method'])
    # set_dpm_boot_params()

    def start(self, guest: CpcPartition, boot_params: dict = None):
        """
        Start a guest

        Performs a start/load/scsi-load action

        Args:
            guest (CpcPartition): guest definition
            boot_params (dict): optional, boot parameters
        """
        partition = self._find_guest(guest)
        if partition.manager.cpc.dpm_enabled:
            # set dpm parameters and activate
            if boot_params:
                self.set_dpm_boot_params(guest, boot_params)
            partition.start()
        else:
            # load classic LPAR
            if partition.prop('status') == 'not-activated':
                partition.activate()

            if not boot_params:
                # load using the address used in the last load.
                partition.load()
                return

            allow_exceptions = boot_params.get(
                'allow_status_exceptions', False)

            if (boot_params['boot_method'] == 'volume'
                    and boot_params['volume_type'] == 'fcp'):
                partition.scsi_load(
                    load_address=self._normalize_address(
                        boot_params['fcp_adapter']),
                    wwpn=boot_params['wwpn'],
                    lun=boot_params['lun'],
                    wait_for_completion=True,
                    allow_status_exceptions=allow_exceptions,
                    force=True,
                    secure_boot=boot_params.get('secure_boot', False)
                )
            elif (boot_params['boot_method'] == 'volume'
                    and boot_params['volume_type'] == 'dasd'):
                store_status = boot_params.get('store_status_indicator', False)
                partition.load(
                    load_address=self._normalize_address(
                        boot_params['volume_id']),
                    wait_for_completion=True,
                    allow_status_exceptions=allow_exceptions,
                    store_status_indicator=store_status,
                    force=True)
            else:
                # non-dpm: only 'volume' method is supported
                logger.warning("Unsupported boot_method %s for partition %s",
                               boot_params['boot_method'], guest.partition_name)
    # start()

    def stop(self, guest: CpcPartition):
        """Stop a guest"""
        partition = self._find_guest(guest)
        logger.info("Stopping partition %s", guest.partition_name)
        partition.stop()
    # stop()

    def update_properties(self, guest: CpcPartition, props: dict):
        """Update parition properties"""
        partition = self._find_guest(guest)
        updated_keys = props.keys()
        logger.debug("Updating partition %s properties %s",
                     partition.name, list(updated_keys))
        # unless we only update boot parameters, partitions have to be
        # stopped/deactivated
        needs_restart = not all(key.startswith('boot-') or key == 'secure-boot'
                                for key in updated_keys)

        partition.update_properties(props)
        if needs_restart:
            partition.stop()
            if not partition.manager.cpc.dpm_enabled:
                partition.deactivate()
    # update_properties()

# HmcSession


class HmcNotifications:
    """
    HMC notifications channel

    Messages are read by a separate thread by zhmcclient.NotificationReceiver
    and buffered until requested with get_messages()

    There are many notification types that can be subscribed to.
    """

    def __init__(self, reconnect_function, *,
                 max_queued_messages=MAX_QUEUED_NOTIFICATIONS):
        """
        Create an async reader from notifications channel

        Args:
            reconnect_function (Callable[[], zhmcclient.NotificationReceiver]):
                a function returning a NotificationReceiver object
        """
        # Reconnection function: called when the connection is lost
        self._reconnect_fn = reconnect_function
        # Channel: communication channel
        self._channel: zhmcclient.NotificationReceiver = None
        # Received message: messages are stored here
        self._received_messages = Queue(max_queued_messages)
        # Error queue for JSM errors. Unbounded errors seems like not a good idea,
        # but we don't want to block the thread.
        self._errors = SimpleQueue()
        # Poll thread: reads messages from the channel
        self._poll_thread = None
        # close: do not read any more messages and do not reconnect
        self._closed = threading.Event()
    # __init__()

    def __enter__(self):
        """
        Context managing entrypoint
        """
        self._channel = self._reconnect_fn()
        self._start_reading()
        return self
    # __enter__()

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Context managing exit point

        Having context assures that this object owns communication channel
        and will close it after it is no longer needed
        """
        self.close()
    # __exit__()

    def _read_from_channel(self):
        """
        Retrieve pending HMC notifications, which may contain several messages

        Reading notifications is a blocking procedure and stalls an event loop,
        so this method should be run in a separate thread
        """
        spam_rate = 60  # seconds between writing a warning message
        last_not_open = datetime.now(TZINFO) - timedelta(seconds=spam_rate)
        last_error = last_not_open

        try:
            # Thread can be exited by setting the event flag
            # A small timeout is set here to prevent hot looping
            while not self._closed.wait(0.2):
                if not self._channel:
                    if (timedelta(seconds=spam_rate) >
                            datetime.now(TZINFO) - last_not_open):
                        last_not_open = datetime.now(TZINFO)
                        self._errors.put({
                            'error': 'Notifications channel is not open',
                            'timestamp': last_not_open
                        })
                    continue

                try:
                    for headers, message in self._channel.notifications():
                        self._received_messages.put({
                            'headers': headers,
                            'message': message,
                            'timestamp': datetime.now(TZINFO)
                        })
                        if self._closed.is_set():
                            break
                except zhmcclient.NotificationJMSError as jms_error:
                    if (timedelta(seconds=spam_rate) >
                            datetime.now(TZINFO) - last_error):
                        last_error = datetime.now(TZINFO)
                        self._errors.put({
                            'error': jms_error,
                            'timestamp': last_error
                        })

        except Exception:   # pylint:disable=broad-except
            # Catch any exception and pass it further
            self._errors.put(
                {'error': sys.exc_info(), 'timestamp': datetime.now(TZINFO)})
    # _read_from_channel()

    def _start_reading(self):
        """
        Start a notification reading thread
        """
        if not self._poll_thread:
            self._poll_thread = Thread(
                name="hmc-listener", target=self._read_from_channel,
                # during testing thread gets stuck after program exit,
                # so we set daemon here
                daemon=True)
            self._poll_thread.start()
    # _start_reading()

    def close(self):
        """
        Close the connection to the HMC

        This method is called when the object is no longer needed
        """
        self._closed.set()
        if self._channel:
            self._channel.close()
            self._channel = None
        if self._poll_thread:
            self._poll_thread.join(timeout=5.0)
            self._poll_thread = None

    def get_notification(self, timeout=5.0):
        """
        Get a single notification from notification channel.
        Blocking call up to timeout seconds

        Args:
            timeout (float): max seconds to wait

        Returns:
            dict: message
        """
        try:
            return self._received_messages.get_nowait()
        except Empty:
            pass

        # No queued notifications - check what's up with the channel
        if self._closed.is_set():
            return None

        if not self._channel:
            # Channel is lost - reconnect
            # Note that reconnect may raise,
            # and we want exceptions to be propagated in caller thread,
            # not in our listener
            self._channel = self._reconnect_fn()
        if self._poll_thread is None or not self._poll_thread.is_alive():
            self._start_reading()

        try:
            return self._received_messages.get(timeout=timeout)
        except Empty:
            pass

        return None
    # get_notification()

    def get_queued_notifications(
            self, message_limit=MAX_RETURNED_MESSAGES_PER_CALL):
        """
        Get all queued notifications (non-blocking)

        Args:
            message_limit (int): maximum number of messages to return

        Returns:
            list: list of messages
        """
        messages = []
        try:
            while len(messages) < message_limit:
                messages.append(self._received_messages.get_nowait())
        except Empty:
            pass
        return messages
    # get_queued_notifications()

    def get_errors(self) -> list:
        """
        Get error messages.

        Returns:
            list: error messages in queue
        """
        result = []
        try:
            while True:
                result.append(self._errors.get_nowait())
        except Empty:
            return result
    # get_errors()

# HmcNotifications


class OsMessages(HmcNotifications):
    """
    Retrieve OS messages for a partition
    """

    def __init__(self, hmc_session: HmcSession, guest: CpcPartition):
        """
        Create OsMessages instance

        Args:
            hmc_session (HmcSession): HMC session
            guest (CpcPartition): guest partition
        """
        super().__init__(self._reconnect)
        self._guest = guest
        self._hmc_session = hmc_session
        self._last_sequence_nr = 0
    # __init__()

    def _reconnect(self):
        """
        Reconnect to HMC notifications

        Returns:
            zhmcclient.NotificationReceiver: notifications session
        """
        if not self._hmc_session.connected:
            logger.info("Not connected to HMC, attempting to reconnect")
            self._hmc_session.connect()
            # still no connection
            if not self._hmc_session.connected:
                logger.warning("Could not reconnect to HMC")
                return None

        topic = self._hmc_session.get_notification_topic(
            HmcNotificationTopic.OS_MESSAGE_TOPIC, self._guest)
        return self._hmc_session.open_notification_receiver(topic)
    # _reconnect()

    def get_messages(self, timeout=5.0):
        """
        Get all messages from notification channel.
        Blocking call up to timeout seconds

        Args:
            timeout (number): max seconds to wait

        Returns:
            List: messages
        """
        # get all messages
        if notification := self.get_notification(timeout=timeout):
            # we got one message with wait; get all the rest without waiting
            rest_notifications = self.get_queued_notifications()
            # OS messages come as another list in the notification body
            os_messages: list = notification['message']['os-messages']
            for entry in rest_notifications:
                os_messages.extend(entry['message']['os-messages'])
        else:
            # fallback: get last messages by a direct call
            os_messages = []
            # os_messages = self._hmc_session.get_os_messages(
            #     self._guest, self._last_sequence_nr)

        if os_messages:
            # In rare cases, e.g. when fallback has received a message,
            # and then it was received again over notifications,
            # we might get duplicates, so we remove them by sequence number.
            new_messages = [
                message['message-text'] for message in
                itertools.dropwhile(
                    lambda msg: int(msg['sequence-number']
                                    ) <= self._last_sequence_nr,
                    os_messages)]
            # Note only start of the list is dropped,
            # because HMC API tells that sequence number may wrap around.

            self._last_sequence_nr = int(os_messages[-1]['sequence-number'])

            # There is still a case where sequence number wraps between
            # two calls, i.e. we have the last possible sequence number,
            # and the next message begins from start.
            # We do not handle this at all.

            return new_messages

        # when no message received - check for errors
        if errors := self.get_errors():
            logger.debug("HMC notifications errors:")
            for error in errors:
                logger.debug("[%s] Exception", error['timestamp'],
                             exc_info=error['error'])

        return []
    # get_messages()
# OsMessages


class HmcConsoleStream(OsMessages, HypStream):
    """
    Stream implementation for Operating System Messages

    This is a base for unix-like terminal interaction.
    """

    def __init__(self, session: HmcSession, guest: CpcPartition):
        logger.debug("Creating HMC console stream for partition %s",
                     guest.partition_name)
        super().__init__(session, guest)
    # __init__()

    def read(self, *, timeout, **kwargs) -> list:
        """
        Read updates from the console as a list of strings

        Args:
            timeout (float): Timeout in seconds
            **kwargs: Additional arguments

        Returns:
            list: List of strings
        """
        item = self.get_messages(timeout=timeout)
        return item
    # read()

    def write(self, data: str, **kwargs) -> None:
        """
        Write data to the console

        Args:
            data (str): Data to write
            **kwargs: Additional arguments
        """
        # HMC API has a limit of 200 chars per call,
        # so we need to split the commands in smaller pieces
        def _string_to_chunks(string, size=200):
            if len(string) < size:
                yield string
                return

            # save command to a temporary file - 'tr' reads stdin as is
            yield "tr -d '\\n' > /tmp/command"
            for start in range(0, len(string), size):
                yield string[start:start+size]

            # stop reading stdin
            yield '^D'
            # run command from temporary file
            yield '. /tmp/command'

        for chunk in _string_to_chunks(data):
            self._hmc_session.send_os_command(chunk, self._guest)
    # write()

# HmcConsoleStream
