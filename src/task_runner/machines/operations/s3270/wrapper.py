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
Wrappers for 3270

Provides layers between ZvmSession to backend
"""


#
# IMPORTS
#
import logging
import time
import re

from enum import Enum

#
# CONSTANTS AND DEFINITIONS
#


#
# CODE
#
logger = logging.getLogger(__name__)


class FieldAttr(Enum):
    """Field attributes (internal use)"""
    STATIC = 1
    INPUT = 2
    HIDDEN = 3
# FieldAttr


def get_changed_rows(origin: list, modified: list):
    """
    Get a slice of changed rows for first to last one
    """
    if len(modified) > len(origin):
        ext_origin = origin + [' '] * (len(modified) - len(origin))
    else:
        ext_origin = origin
    changed_offsets = list(
        offset for offset, (org, tgt) in enumerate(zip(ext_origin, modified))
        if org != tgt)

    if not changed_offsets:
        return []

    return modified[changed_offsets[0]:changed_offsets[-1]+1]
# get_changed_rows()


class ReadException(RuntimeError):
    """Exception updating screen"""

# pylint:disable=too-few-public-methods


class ScreenUpdater:
    """
    Tracks screen changes

    When screen is not formatted or output is presented as streamed lines,
    it is important to find new messages that appeared after an entered command.
    This class keeps previous screen state and reports difference when new
    data is available.
    """

    def __init__(self, area, fn_cmd) -> None:
        """
        Initialize updater

        Arguments:
            area (tuple): screen area for tracking changes, 1-offset.
                Provide 4 integers (row, column, bottom row, right column)
                Bottom and right may be 0 or less for relative positioning
            fn_cmd (callable): s3270 "run command" method
        """
        self._fn_cmd = fn_cmd

        # query current screen size to fixup relative area
        # (see https://x3270.miraheze.org/wiki/S3270_protocol)
        output = self._cmd('Query(ScreenSizeCurrent)')[0].split()
        size = dict(zip(output[::2], map(int, output[1::2])))
        n_rows, n_cols = size['rows'], size['columns']
        self._area = (
            area[0], area[1],
            area[2] if area[2] > 0 else n_rows + area[2] - area[0] + 1,
            area[3] if area[3] > 0 else n_cols + area[3] - area[1] + 1)
        self._snap_area = f'Snap(Ascii1,{",".join(map(str,self._area))})'
        self._ascii_area = f'Ascii1({",".join(map(str,self._area))})'
        # get previous screen state
        self._screen = self._cmd(self._snap_area)
    # __init__()

    def get_update(self, timeout: float):
        """
        Get screen update

        Wait for the update (or timeout) and report difference to previous
        screen state

        Arguments:
            timeout (float): how long to wait for screen to update
        """
        # wait for the update. Note that as of 4.1 timeout should be integer
        # (see 3270:Common/task.c "Snap_action")
        # self._cmd(f"Snap(Wait,{int(self._timeout)},Output)")
        self._cmd(f"Wait({max(1.0, timeout):.2f},Output)")
        try:
            self._cmd("Snap(save)")
            output = self._cmd(self._snap_area)
        except ReadException as exc:
            if 'Not connected' in str(exc):
                output = self._cmd(self._ascii_area)
            else:
                raise

        # logger.info(output)
        diff = get_changed_rows(self._screen, output)
        # find difference between screen and output
        self._screen = output
        return diff
    # get_update()

    def _cmd(self, command):
        """Run a command with check"""
        status, output = self._fn_cmd(command)
        if status != 'ok':
            raise ReadException(output)
        return output
    # _cmd()

# ScreenUpdater


class ScreenWrapper:
    """
    Wrapper for screen grabbing

    Provides output stream for 3270 screen updates
    """

    def __init__(self, connection) -> None:
        """Initialize wrapper"""
        self._s3270 = connection
    # __init__()

    def disconnect(self):
        """Disconnect from underlying 3270"""
        self._s3270.terminate(final_cmd='Quit')
    # disconnect()

    def get_field_attrs(self):
        """Retrieve active field attributes"""
        field_desc = self.send("ReadBuffer(Field)")
        field_contents = [line for line in field_desc
                          if line.startswith('Contents:')][0]
        # pick first 'c0' attribute setting for the field,
        # it sets basic attributes for the field (though can be overridden)
        field_attr = [field for field in field_contents.split()
                      if 'c0=' in field][0]
        # field_attr looks like SF(c0=..) or SA(c0=..)
        # Pick the value
        value = int(field_attr.split('=')[1][:2], 16)
        attrs = set()
        if value & 0x0c == 0x0c:
            attrs.add(FieldAttr.HIDDEN)
        if value & 0x20:
            attrs.add(FieldAttr.STATIC)
        elif not value & 0x02:
            attrs.add(FieldAttr.INPUT)
        return attrs
    # get_field_attrs()

    def get_status(self):
        """Retrieve last known status"""
        output = self.send('Query(ScreenSizeCurrent)')[0].split()
        size = dict(zip(output[::2], map(int, output[1::2])))
        snap_status = f'Snap(Ascii1,{size["rows"]},{size["columns"]-19},7)'
        return self.send(snap_status)[0]
    # get_status()

    def send(self, command: str):
        """Send command"""
        if re.match('string', command, re.IGNORECASE):
            # check if string is entered into a non-displayed field,
            # and so its logging should be hidden as well
            hide = FieldAttr.HIDDEN in self.get_field_attrs()
        else:
            hide = False

        status, output = self._s3270.run(command, hide=hide)
        if status != 'ok':
            raise ReadException(output)
        return output
    # send()

    def output_stream(self, *, timeout, area, autoscroll=True):
        """
        Return output stream generator

        Args:
            timeout (float): timeout in seconds to wait for changes
            area (tuple): area to scan for changes
            autoscroll (bool): send Clear automatically when screen buffer
                overflowed
        """
        end = time.monotonic() + timeout
        updater = ScreenUpdater(area, self._s3270.run)
        while (current_time := time.monotonic()) < end:
            try:
                diff = updater.get_update(end - current_time)
            except ReadException:
                break
            logger.info('\n%s', '\n'.join(diff))
            # yield
            if diff:
                yield diff

            # autoscroll
            if autoscroll and self.get_status() in ('MORE...', 'HOLDING'):
                self.send('Clear')

            # short nap to avoid hot loop when get_update does not wait
            time.sleep(0.1)

    # output_stream()

# ScreenWrapper
