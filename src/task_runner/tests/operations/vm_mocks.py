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

from queue import Empty, Queue
from threading import Event, Thread
from time import monotonic
import re
import time

from .vm_apps import LogonApp, CpApp, AppResponse

#
# CONSTANTS AND DEFINITIONS
#

# How long backend works without commands, seconds
# Provides quick test finish even on fails
BACKEND_TIMEOUT = 4.0


#
# CODE
#

# Connection mock helpers
def _err():
    """Connection mock error"""
    return 'error', []


def _ok(output=None):
    """Connection mock success"""
    if output is None:
        return 'ok', []
    return 'ok', output


class BackendMock:
    """
    Custom 3270 backend

    Provides mocked response with a delay
    """
    # pylint:disable=too-many-instance-attributes

    def __init__(self, initial_app='logon') -> None:
        self._from_backend_queue = Queue()
        self._to_backend_queue = Queue()
        self._delay = 0.15  # processing delay in seconds
        self._active_app = initial_app
        self._apps = {
            'logon': LogonApp(),
            'cp': CpApp(),
        }
        self._work_thread = None
        self._stop_thread = Event()
        self._response_queue = []

    def _exec(self, command: str):
        """Command execution - high-level logic applies"""
        app = self._apps[self._active_app]

        # this can collide with a simple string "clear", but
        # we just make sure it does not happen in tests
        if command.lower() == 'clear':
            app.clear()
        else:
            app.input(command)

    def _put_response(self, response: AppResponse):
        """Put response to queue"""
        if response.clear:
            self._response_queue.append(('clear',))

        self._response_queue.append(('buffer', response.output))

        if response.activate:
            self._active_app = response.activate[0]
            self._apps[self._active_app].start(*response.activate[1:])

    @property
    def receive_queue(self):
        """Return waitable queue with protocol commands"""
        return self._from_backend_queue

    @property
    def transmit_queue(self):
        """Return send queue for communication"""
        return self._to_backend_queue

    def _thread_proc(self):
        """Thread that operates on apps and queues"""
        # set a hard timeout in case test goes wrong
        end = monotonic() + BACKEND_TIMEOUT

        self._apps[self._active_app].start()

        while (current := monotonic()) < end:
            try:
                command = self._to_backend_queue.get_nowait()
            except Empty:
                command = None

            if command:
                end = current + BACKEND_TIMEOUT
                self._exec(command)
            elif self._response_queue:
                # display responses only on next cycle
                self._from_backend_queue.put(self._response_queue.pop(0))
            else:
                # ask apps if they have more data
                for app in self._apps.values():
                    response = app.get_response()
                    if response:
                        self._put_response(response)

            if self._stop_thread.wait(timeout=self._delay):
                break

    def start(self):
        """Start backend thread"""
        self._stop_thread.clear()
        self._work_thread = Thread(target=self._thread_proc, name='backend')
        self._work_thread.start()

    def stop(self):
        """Stop backend thread"""
        self._stop_thread.set()
        self._work_thread.join()
# BackendMock


class TerminalMock:
    """
    Custom 3270 terminal class

    Mocks 3270 terminal for some queries and actions
    """

    def __init__(self, screen_size=(43, 80)) -> None:
        """Initialize screen"""
        self._connected = False
        self._buffer = []
        self._input_string = ''  # command entry at -2 from bottom
        self._disp_status = ''  # displayed status at -1 from bottom
        self._screen_size = screen_size
        self._backend = BackendMock()

    def _clear(self):
        """Clear one screen"""
        self._buffer = self._buffer[self._screen_size[0] - 2:]

    def _display_buffer(self):
        """Prepare buffer for display"""
        height, width = self._screen_size
        result = [line.ljust(width) for line in self._buffer[:height-2]]
        result.extend([' ' * width] * max(0, height - 2 - len(result)))
        result.append(self._input_string.ljust(width))
        if len(self._buffer) > height - 2:
            status = 'MORE...'
        else:
            status = self._disp_status
        result.append(status.rjust(width))
        return result

    def _partial_buffer(self, row, col, *argv) -> list:
        """
        Return part of screen buffer

        Row and col indices are 1-based

        Arguments:
            row, col: starting row and column
            argv may be:
                n_fields: number of characters to read
                n_rows, n_cols: how many rows and columns to read
        """
        if len(argv) == 1:
            n_characters = argv[0]
            return self._partial_char_buffer(row, col, n_characters)

        screen = self._display_buffer()
        n_rows, n_cols = argv[0], argv[1]
        result = [line[col-1:n_cols] for line in screen[row-1:n_rows]]
        return result

    def _partial_char_buffer(self, row, col, n_chars) -> list:
        """
        Return part of screen buffer ranged by character count.

        Row and col are 1-based. If n_chars overflows screeen width,
        each next line is a new string in the result
        """
        screen = self._display_buffer()
        screen_width = self._screen_size[1]
        assert len(screen) == self._screen_size[0]
        # first line
        first_line_len = min(screen_width - col + 1, n_chars)
        result = [screen[row-1][col-1:col - 1 + first_line_len]]

        rest = n_chars - first_line_len
        if rest == 0:
            return result

        n_full_lines = rest // 80
        # wrap to have next line at top
        wrap_screen = screen[row:] + screen[:row]
        if n_full_lines > 0:
            # add full screen lines wrapping around the bottom to top
            result.extend(wrap_screen[n_full_lines-1])
        # final line
        result.append(wrap_screen[n_full_lines][:rest % 80])
        return result

    def _process_input(self, input_string: str):
        """Input and process string"""
        parts = input_string.splitlines(keepends=True)
        for part in parts:
            if '\n' in part:
                self._backend.transmit_queue.put(part[:-1])
            else:
                self._input_string = part

    def _process_proto(self, response: tuple):
        """Process backend response"""
        if response[0] == 'clear':
            self._clear()
        elif response[0] == 'buffer':
            self._buffer.extend(response[1])
        elif response[0] == 'status':
            self._disp_status = response[1]

    def _set_displayed_status(self, status):
        """Set status in the last line of text (e.g. RUNNING or VM READ)"""
        self._disp_status = status

    def get_status(self):
        """Get displayed status"""
        return self._disp_status

    # pylint:disable=too-many-return-statements,too-many-branches
    def run(self, command: str, hide: bool = False):
        """Return response"""
        verb = re.findall(r'[\w\.]+', command.lower())
        if verb[:2] == ['query', 'screencursize']:
            return _ok([f'{self._screen_size[0]} {self._screen_size[1]}'])
        if verb[:2] == ['query', 'screensizecurrent']:
            return _ok([f'rows {self._screen_size[0]} '
                        f'columns {self._screen_size[1]}'])
        if verb[:2] == ['query', 'version']:
            return _ok(['s3270 v4.1ga11 Thu Mar 10 22:39:14 UTC 2022 user'])
        if verb[:2] == ['query', 'host']:
            if self._connected:
                return _ok(['vm.example.com'])
            return _ok([''])
        if verb[:2] == ['readbuffer', 'field']:
            return _ok(['Start1: 40 16', 'Cursor1: 40 17',
                        'Contents: SF(c0=c0) 00 00 00 00 00 00 00 00'])
        if verb[:] == ['snap', 'ascii1']:
            # complete buffer
            return _ok(self._display_buffer())
        if verb[:2] == ['snap', 'ascii1']:
            # partial buffer
            return _ok(self._partial_buffer(*map(int, verb[2:])))
        if verb[:2] == ['snap', 'wait']:
            # wait for commands to arrive
            try:
                reply = self._backend.receive_queue.get(timeout=float(verb[2]))
                self._process_proto(reply)
            except Empty:
                pass
            return _ok()
        if verb[0] == 'snap':
            # snap / snap save is implicit; other snap actions are irrelevant
            return _ok()
        if verb[0] == 'wait':
            try:
                reply = self._backend.receive_queue.get(timeout=float(verb[1]))
                self._process_proto(reply)
            except Empty:
                pass
            return _ok()
        if verb[0] == 'string':
            # extract string and process it
            input_string = command[command.find('"') + 1:command.rfind('"')]
            self._process_input(input_string)
            return _ok()
        if verb[0] == 'enter':
            self._process_input(self._input_string + '\n')
            self._input_string = ''
            return _ok()
        if verb[0] == 'clear':
            self._backend.transmit_queue.put('clear')
            return _ok()
        if verb[0] == 'attn':
            self._backend.transmit_queue.put('attn')
            return _ok()
        if verb[0] == 'pause':
            time.sleep(0.3)
            return _ok()
        if verb[0] == 'connect':
            self._connected = True
            self._backend.start()
            return _ok()
        if verb[0] == 'disconnect':
            self._connected = False
            self._backend.stop()
            return _ok()
        if verb[0] == 'error':
            return _err()

        raise NotImplementedError(verb)

    def terminate(self, *_args, **_kwargs):
        """Terminate connection"""
        if self._connected:
            self._connected = False
            self._backend.stop()

# TerminalMock
