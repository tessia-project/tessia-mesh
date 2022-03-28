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
import logging
import re

from dataclasses import dataclass
from ipaddress import AddressValueError, IPv6Address

from .s3270.wrapper import ScreenWrapper
from .s3270.pipeconnector import S3270PipeConnector

#
# CONSTANTS AND DEFINITIONS
#
DEFAULT_CONNECTION_OPTIONS = {
    # port to connect to
    'port': 23,

    # use TLS connection
    'use_tls': False,

    # verify certificate data if TLS is used
    'verify_tls': True,

    # alternative hostname specified in certificate
    'certificate_host': ''
}

# regular expression for variables in commands
VAR_EXPRESSION = re.compile(r'\{([\w\s]+?)\}')

# script interaction defaults
DEFAULT_BEHAVIOUR = {
    # insert Pause command to induce delay (unlockDelayMs) after each command
    'autodelay': True,
    # timeout waiting for changes after command is sent, seconds
    'command_timeout': 15.0,
    # part of screen eligible for streaming (row, column, N rows, N columns)
    # Offsets are 1-based, zero and negative counts are relative to screen size
    'stream_area': (1, 1, -2, 0)
}


# "RPIMGR042I": "PASSWORD EXPIRED",
# "RPIMGR046T": "User ID access has been revoked.",
# "HCPCFC015E": "Command not valid before LOGON",
# "HCPLGA050E": "LOGON unsuccessful--incorrect userid and/or password",
# "HCPLGA054E": "Already logged on",
# "HCPUSO361E": "LOGOFF/FORCE pending for user",
# "HCPLGA361E": "LOGOFF/FORCE pending for user",
LOGON_ERROR_CODES = ['RPIMGR042I', 'RPIMGR046T', 'HCPCFC015E', 'HCPLGA050E',
                     'HCPLGA054E', 'HCPUSO361E', 'HCPLGA361E']

ERROR_REGEX = r'(HCP(?:[a-zA-Z]{0,8})\d{1,4}[E]{1})( .*)?'

# Scripts


#
# CODE
#
logger = logging.getLogger(__name__)


@dataclass
class ZvmHypervisor:
    """
    z/VM hypervisor definition
    """
    hostname: str
    # logonby_credentials: dict = {} do wee need it?
    connection_options: dict

    def __repr__(self) -> str:
        return f'ZvmHypervisor({self.hostname})'
# ZvmHypervisor


@dataclass
class ZvmGuest:
    """z/VM guest"""
    guest_name: str
    credentials: dict

    def __repr__(self) -> str:
        return f'ZvmGuest({self.guest_name})'
# ZvmGuest


def first(seq, default=None, key=None, raise_stop=False):
    """Get first truthy value from sequence"""
    for item in seq:
        if item and (key is None or item[key]):
            return item

    if raise_stop:
        raise StopIteration
    return default
# first()


def substitute_arguments(string, arguments) -> str:
    """Put arguments into a string template"""
    def _sub(match):
        """Get a substitution"""
        if (grp := match.group(1)) in arguments:
            return arguments[grp]
        return match.group(0)

    return VAR_EXPRESSION.sub(_sub, string)
# substitute_arguments()


def _err_matcher(output, match, _arguments):
    """Callback used in default scripts on error matching"""
    logger.error('Found error in output: %s', match.group(0))
    logger.debug('Error context:')
    logger.debug(output)
# _err_matcher()


class ZvmSession:
    """z/VM session"""

    def __init__(self, hypervisor: ZvmHypervisor) -> None:
        """Initialize hypervisosr"""
        self._hypervisor = hypervisor
        self._connection_options = DEFAULT_CONNECTION_OPTIONS.copy()
        self._connection_options.update(hypervisor.connection_options)
        self._connection_string = self._format_connection_string()

        self._terminal = None
    # __init__()

    @staticmethod
    def _normalize_address(address):
        """
        Convert the load address to the format expected by z/VM
        (4 hex digits)

        Args:
            address (str): string in the format 0.0.1500 or 1500

        Returns:
            str: normalized load address
        """
        return address.replace('.', '')[-4:]
    # _normalize_address()

    def _format_connection_string(self):
        """Return connection string for the specified hypervisor"""
        # see host string syntax at
        # https://x3270.miraheze.org/wiki/Host_name_syntax
        try:
            host_string = f'[{IPv6Address(self._hypervisor.hostname)}]'
        except AddressValueError:
            host_string = self._hypervisor.hostname

        host_string += f":{self._connection_options['port']}"
        if self._connection_options['use_tls']:
            if self._connection_options['verify_tls']:
                host_string = f'L:{host_string}'
                if self._connection_options['certificate_host']:
                    host_string = (
                        f"{host_string}="
                        f"{self._connection_options['certificate_host']}")
            else:
                host_string = f'L:Y:{host_string}'
        return host_string
    # _format_connection_string

    def compatible(self, other_hypervisor) -> bool:
        """Test if hypervisor definitions are similar"""
        return (isinstance(other_hypervisor, ZvmHypervisor)
                and other_hypervisor == self._hypervisor)
    # compatible()

    def connect(self):
        """Connect to z/VM hypervisor"""
        if not self._terminal:
            logger.debug("Creating s3270 pipe connection")
            conn = S3270PipeConnector()
            self._terminal = ScreenWrapper(conn)

        current_host = self._terminal.send('Query(Host)')[0]
        if not current_host:
            logger.info("Connecting to z/VM %s", self._hypervisor.hostname)
            self._terminal.send(f'Connect({self._connection_string})')
        else:
            logger.info("Already connected to %s", current_host)
    # connect()

    def disconnect(self):
        """Disconnect from hypervisor"""
        if self._terminal:
            logger.info("Disconnecting from z/VM %s",
                        self._hypervisor.hostname)
            self._terminal.disconnect()
            self._terminal = None
    # disconnect()

    def ipl_cms(self, acc_opts: str):
        """Start CMS"""
        cms_script = [
            {'command': 'String("ipl cms\n")',
             'match': {'re': re.compile('z/VM')}},
            {'command': f'String("access ({acc_opts})\n")',
             'match': [
                 {'re': re.compile('Ready;'), 'stop': 'ok'},
                 {'re': re.compile('system reset'), 'stop': 'err'},
             ]},
        ]
        result = self.run_script(cms_script, {'acc_opts': acc_opts})
        if result == 'ok':
            return result
        if not self.is_guest_ipled():
            # try again, could be profile exec doing something resetting
            return self.run_script(cms_script, {'acc_opts': acc_opts})
        return None
    # ipl_cms()

    def ipl_from_volume(self, boot_params: dict):
        """
        IPL from DASD or FCP volume
        """
        def _pad(device_id: str):
            """Pad device ID to 8 or 16 characters and split if needed"""
            pad_len = 8 if len(device_id) <= 8 else 16
            device_str = device_id.ljust(pad_len, '0')

            if pad_len > 8:
                device_str = device_str[:8] + ' ' + device_str[8:]
            return device_str
        # _pad()

        err_regex = re.compile(ERROR_REGEX)
        ipl_device_script = [
            {'command': 'String("q v {device}\n")',
             'match': {'re': err_regex, 'stop': 'err'},
             'behaviour': {'command_timeout': 2.0}},
            {'command': 'String("ipl {device}\n")',
             'match': {'re': err_regex, 'stop': 'err'}},
        ]
        prepare_fcp_script = [
            {'command': 'String("set loaddev portname {port} lun {lun}\n")'},
            {'command': 'String("q loaddev\n")',
             'match': {'re': re.compile('PORTNAME .* LUN')},
             'behaviour': {'command_timeout': 2.0}}
        ]
        if boot_params['volume_type'] == 'fcp':
            ipl_device = self._normalize_address(boot_params['fcp_adapter'])
            # set loaddev address
            result = self.run_script(prepare_fcp_script, {
                'port': _pad(boot_params['wwpn']),
                'lun': _pad(boot_params['lun']),
                'adapter': ipl_device
            })
            if result is not None:
                # error happened
                return result
        else:
            ipl_device = self._normalize_address(boot_params['volume_id'])

        result = self.run_script(ipl_device_script, {
            'device': ipl_device
        })
        if result is None:
            return 'ok'

        return result
    # ipl_from_volume()

    def is_guest_ipled(self):
        """
        Test if the guest has something running

        Even if logon is performed with "noipl", the session might reconnect
        to a running guest. The indicator for this is a "RUNNING" or "VM READ"
        state (this is not always the case, but should do for the use cases)
        """
        if not self._terminal:
            return False
        return self._terminal.get_status() != 'CP READ'
    # is_guest_ipled()

    def logoff(self, leave_running: bool = True):
        """
        Logoff from the guest
        """
        logoff_script = [
            {'command': 'Clear'},
            {'command': 'String("#cp logoff\n")',
             'behaviour': {'autodelay': False},
             'match': {'re': re.compile('LOGOFF AT'), 'stop': 'ok'}}
        ]
        disconnect_script = [
            {'command': 'Clear'},
            {'command': 'String("#cp disc\n")',
             'behaviour': {'autodelay': False},
             'match': {'re': re.compile('DISCONNECT AT'), 'stop': 'ok'}}
        ]
        # We don't check return codes, because host will disconnect after the
        # action. It also seems that match will not happen, because
        # snap(wait, output) ends with "error" on a disconnect
        if leave_running:
            self.run_script(disconnect_script, {})
        else:
            self.run_script(logoff_script, {})
        self.disconnect()
    # logoff()

    def logon(self, parameters: dict):
        """Logon to z/VM guest"""
        logon_script = [
            {'command': 'Clear',
             'match': {'re': re.compile('LOGON userid')}},
            {'command': 'String("logon {guest} here noipl {by_user}\n")',
             'match': {'re': re.compile('Enter your password')}},
            {'command': 'String("{password}\n")',
             'match': [
                 {'re': re.compile('z/VM Version'), 'stop': 'ok'},
                 {'re': re.compile('|'.join(LOGON_ERROR_CODES)),
                     'stop': 'err', 'callback': _err_matcher}
             ]},
        ]

        logon_arguments = {
            'guest': parameters['guest_name'],
            'by_user': parameters.get('logon_by', ''),
            'password': parameters['password'],
        }
        if logon_arguments['by_user']:
            logon_arguments['by_user'] = f"by {logon_arguments['by_user']}"
        return self.run_script(logon_script, logon_arguments)
    # logon()

    def reset(self):
        """Reset VM guest"""
        reset_script = [
            {'command': 'String("#cp sys clear\n")',
             'match': {'re': re.compile('Storage cleared'), 'stop': 'ok'}},
            {'command': 'Attn'},
            {'command': 'String("sys clear\n")',
             'match': {'re': re.compile('Storage cleared'), 'stop': 'ok'}},
        ]

        # mash keyboard until "sys clear" gets through
        for _repeats in range(1, 5):
            if (response := self.run_script(reset_script, [])) is not None:
                return response
        return None
    # reset()

    # pylint:disable=too-many-locals,too-many-branches
    def run_script(self, script: list, arguments: dict,
                   script_behaviour: dict = None):
        """
        Run a script

        Each script entry is a dictionary:
            "command": a s3270 script command
                (see https://x3270.miraheze.org/wiki/Category:S3270_actions)
            "match": dict (or list of dict) that represents action
                     for matching output
                "re": regexp **object** to use for matching
                "callback": (optional) callback to call on match
                    with signature fn(output, match, arguments).
                    The callback can update arguments on the fly
                "stop": (optional) stop execution, provides result
                    to return to caller
                Default action on match is to continue to next script step.
                A list of matches is tested sequentially until match is found,
                then the appropriate action is taken.
            "behaviour": (optional) dict with behaviour overrides

        Args:
            script (list): a list of commands to pass over client and
                strings to expect as an answer
            arguments (dict): variables to substitute into script
                Arguments are **mutable** and can be updated by callback
                functions with immediate effect on future steps
            script_behaviour (dict): interaction settings
                "autodelay": insert a Pause after every command
                "command_timeout": how long to wait for command output.
                    Commands without match are not checked; commands with
                    a match or global error checking are waited for the
                    whole timeout duration. It is recommended to always
                    provide a successful match expression.
                "stream_area": area of interest for output detection.
                    Defaults to whole screen without two bottom lines
        """
        if not self._terminal:
            self.connect()

        default_behaviour = DEFAULT_BEHAVIOUR.copy()
        if script_behaviour is not None:
            default_behaviour.update(script_behaviour)

        def _process_match(match_dict, matched, output_lines):
            """
            Process a found match
            """
            if callback := match_dict.get('callback'):
                callback(output_lines, matched, arguments)
            if 'stop' in match_dict:
                # stop and return any value that is there (even falsey)
                return ('stop', match_dict.get('stop'))
            return ('continue',)
        # _process_match()

        def _match_err(_output_lines, matched, *argv):
            """
            Callback for an error match
            """
            raise RuntimeError("Error detected: " + matched.string.strip())
        # _match_err()

        # initial screen snapshot
        self._terminal.send('Snap(Save)')

        for entry in script:
            command_behaviour = default_behaviour
            command = substitute_arguments(entry['command'], arguments)
            logger.info('Script step: %s',
                        entry['command'].replace('\n', r'\n'))

            cmd_match = entry.get('match')
            if overrides := entry.get('behaviour'):
                command_behaviour = default_behaviour.copy()
                command_behaviour.update(overrides)

            # convert match / matches to a regex scan list
            if cmd_match and isinstance(cmd_match, dict):
                match_list = [(cmd_match['re'], cmd_match)]
            elif cmd_match and isinstance(cmd_match, list):
                match_list = [(match['re'], match) for match in cmd_match]
            else:
                match_list = []
            for match_err in command_behaviour.get('errors', []):
                match_list.append((match_err, {'callback': _match_err}))

            self._terminal.send(command)
            if command_behaviour['autodelay']:
                self._terminal.send('Pause')

            # wait for output change
            logger.debug('Match list: %s',
                         [match.pattern for match, _ in match_list])
            if match_list:
                for output_lines in self._terminal.output_stream(
                        timeout=command_behaviour['command_timeout'],
                        area=command_behaviour['stream_area']):

                    # check for match - one from the list regexp at a time
                    try:
                        match_re, match_dict, matched = first(
                            ((match_re, match_dict,
                              first(match_re.search(line)
                                    for line in output_lines))
                             for match_re, match_dict in match_list),
                            key=2, raise_stop=True
                        )
                    except StopIteration:
                        # no matching entry - wait for more output
                        continue

                    logger.debug("Output match for %s", match_re.pattern)
                    ret = _process_match(match_dict, matched, output_lines)
                    if ret[0] == 'stop':
                        logger.info("Script stopped with %s", ret[1])
                        return ret[1]

                    # we get here after match was processed,
                    # move on to next item
                    break
            # end of output processing

            # continue to next line in script
            logger.debug("Script step finished")

        # end of script reached
        logger.info("Script completed")

    # run_script()


# ZvmSession
