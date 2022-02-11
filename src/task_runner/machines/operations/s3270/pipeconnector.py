# Copyright 2016-2022 IBM Corp.
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
S3270 Pipe connector class
"""
#
# IMPORTS
#
import logging
import re
import subprocess
import time

from enum import Enum
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE

#
# CONSTANTS AND DEFINITONS
#
HIDE_MARKER = '[*INPUT NOT DISPLAYED*]'
# Possible status messages from s3270 terminal
STATUS = [b'ok', b'error']
# Maximum s3270 data line size ('data: ' + 80 characters + line break)
ROW_SIZE = 87

# default timeout for piped commands, seconds
DEFAULT_COMMAND_TIMEOUT = 30

#
# CODE
#

logger = logging.getLogger(__name__)


class Feature(Enum):
    """Important processing features that may be present in s3270 backend"""
    # has 1-offset Ascii1 and similar commands
    ONE_OFFSET = 1
    # has Pause command to emulate unlockDelay
    PAUSE = 2
# Feature


class S3270PipeConnector:
    """
    This class encapsulates the reading from and writing to an s3270 process
    pipe. The objective is to be a connector to the s3270 process.
    """

    def __init__(self):
        """
        Initialize s3270 process and communication
        """
        # create new s3270 process and connects to its pipes
        # pylint: disable=consider-using-with
        self._s3270 = subprocess.Popen(
            [
                's3270',
                '-model',
                '3278-4',
                '-utf8',
            ],
            bufsize=0,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )

        # set poll object to wait for content on stdin/stdout
        self._reader = DefaultSelector()
        self._writer = DefaultSelector()

        self._reader.register(self._s3270.stdout, EVENT_READ)
        self._writer.register(self._s3270.stdin, EVENT_WRITE)

        self._features = self._feature_detect()
    # __init__()

    def _trasform_command(self, cmd: str) -> str:
        """
        Change command to match the detected feature set
        """

        def _area_fixup(area):
            """Convert 1-offset to 0-offset"""
            positions = area.split(',')
            if len(positions) >= 3:
                # row, col, (length or rows, columns)
                # only row and rol should be made 0-offset
                positions[0] = str(int(positions[0]) - 1)
                positions[1] = str(int(positions[1]) - 1)
                return ','.join(positions)
            return area
        # _area_fixup()

        match = re.match(r'(\w+)(\((.*)\))?', cmd, re.DOTALL)
        verb, args = match.group(0).lower(), match.group(2)
        if verb == 'pause':
            if Feature.PAUSE not in self._features:
                return 'Wait(0.3,seconds)'

        elif verb == 'ascii1':
            if args is not None and Feature.ONE_OFFSET not in self._features:
                new_offsets = _area_fixup(args)
                return f'Ascii({new_offsets})'

        elif verb == 'snap':
            snap_verb, snap_args = (args.split(',', maxsplit=1) + [''])[:2]
            if snap_verb.lower() == 'ascii1':
                if Feature.ONE_OFFSET not in self._features:
                    new_offsets = _area_fixup(snap_args)
                    return f'Snap(Ascii,{new_offsets})'

        # convert escape sequences
        return cmd.replace('\n', '\\n').replace('\t', '\\t')
    # _trasform_command()

    def _feature_detect(self):
        """
        Find which features are present (based on version query)
        to work around for them in scripts
        """
        status, output = self.run('Query(Version)')
        if status == 'error':
            # earlier than version 4
            logger.info("Connected to s3270 3.x")
            return set()
        version_string = output[0]
        logger.info("Connected to %s", version_string)

        if match := re.match(r'v?(\d+\.\d+)', version_string.split()[1]):
            version = match.group(1)
        else:
            return set()

        major, minor = version.split('.')
        if major == 4 and minor == 0:
            return {Feature.ONE_OFFSET}
        return {Feature.ONE_OFFSET, Feature.PAUSE}
    # _feature_detect

    def _read(self, timeout):
        """
        Perform low level reading from s3270 stdout. This is intended to be
        used internally only.

        Args:
            timeout (float): how many seconds to wait for an output

        Returns:
            str: last line of s3270 terminal with status message
            str: whole output content from s3270 terminal

        Raises:
            TimeoutError: if while receiving output we reaches timeout
                          specified
        """
        # define the timeout limit
        end_time = time.monotonic() + timeout

        # buffer for content read
        output = b''

        # There may be multiple reads needed to obtain the whole response,
        # so we establish a global timeout for the operation.
        while (current_time := time.monotonic()) < end_time:
            # Select returns once data becomes available
            events = self._reader.select(timeout=end_time-current_time)
            for key, _ in events:
                output += key.fileobj.read(ROW_SIZE)

            # Finish operation if 'ok' or 'error' found
            if output.rsplit(maxsplit=1)[-1] in STATUS:
                output = output.decode()
                # return status and output
                return (output.rsplit(maxsplit=1)[-1], output)

        # timeout reached: raise exception
        logger.debug('content read: %s', output)
        raise TimeoutError('Timeout while reading output')
    # _read()

    def _write(self, cmd: str, timeout):
        """
        Perform low level writing to s3270 stdin. This is intended to be used
        internally only.

        Args:
            cmd (str): s3270 command
            timeout (float): how many seconds to wait for stdin to be ready

        Raises:
            TimeoutError: if stdin is not available
        """
        # command arrives without newline control character
        cmd = cmd+'\n'

        # define the timeout limit
        end_time = time.monotonic() + timeout

        # Since Python 3.5 `select` should not return empty lists,
        # but we'll keep the outer timeout loop just in case.
        # https://docs.python.org/3/library/selectors.html#selectors.BaseSelector.select`
        while (current_time := time.monotonic()) < end_time:
            events = self._writer.select(timeout=end_time-current_time)
            for key, _ in events:
                key.fileobj.write(cmd.encode('utf-8'))
                return

        # timeout reached: raise exception
        logger.debug('stdin not available')
        raise TimeoutError('Could not write on stdin')
    # _write()

    def quit(self, timeout=DEFAULT_COMMAND_TIMEOUT):
        """
        Execute a 'Quit' command and return.

        Args:
            None

        Raises:
            None
        """
        # write command to s3270 stdin
        self._write('Quit', timeout)

        # clean up process
        self.terminate()
    # quit()

    def run(self, cmd, timeout=DEFAULT_COMMAND_TIMEOUT, hide=False):
        """
        Execute a command and wait 'timeout' seconds for the output. This
        method is the entry point to be consumed by users.

        Args:
            cmd (str): s3270 command
            timeout (float): how many seconds to wait for an output to complete
            hide (bool): whether the command is sensitive (i.e. password) and
                         should be suppressed in the log

        Returns:
            str: last line of s3270 terminal with status message
            str: whole output content from s3270 terminal

        Raises:
            None
        """
        transformed_cmd = self._trasform_command(cmd)
        # mask string inputs for debug
        logger.debug('[input]:%s', HIDE_MARKER if hide else transformed_cmd)
        # write command to s3270 stdin
        self._write(transformed_cmd, timeout)
        # read status and output from stdout
        (status, output) = self._read(timeout)

        # only leave data lines
        return (status, [line[6:] for line in output.splitlines()
                         if line.startswith('data: ')])
    # run()

    def terminate(self, final_cmd: str = None, timeout=DEFAULT_COMMAND_TIMEOUT):
        """
        Terminate process execution and clean up object.

        Args:
            final_cmd (str): last command to send

        Raises:
            None
        """
        # communicate wait for the process to end
        try:
            self._s3270.communicate(
                input=(final_cmd + '\n').encode('utf-8'), timeout=timeout)
        except subprocess.TimeoutExpired:
            # kill the process otherwise
            self._s3270.kill()
            # and try to communicate again to clean up defunct
            self._s3270.communicate(timeout=timeout)

        # clean up object
        self._s3270 = None
    # terminate()

# S3270PipeConnector
