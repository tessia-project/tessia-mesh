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
Power Manager actions
"""

# pylint:disable=too-few-public-methods
# Common for all classes here, which mostly store a dataset and provide
# one operation to act on it within a hypervisor context

#
# IMPORTS
#
import logging

from ..operations.hmc import HmcSession
from ..operations.zvm import ZvmSession

#
# CONSTANTS AND DEFINITIONS
#


#
# CODE
#
logger = logging.getLogger(__name__)


class PoweronAction:
    """Power on a machine"""

    def __init__(self, guest, parameters) -> None:
        """Initialize action"""
        self._guest = guest
        self._parameters = parameters
        #
        # #### LPAR ####
        #
        # empty parameters: boot last location
        #
        # boot_method == 'volume':
        #   volume_type == 'fcp':
        #     - DPM requires uuid to have a storage group match
        #     - non-DPM requires 'fcp_adapter', 'wwpn', 'lun'
        #     Both allow 'secure_boot' option
        #   volume_type == 'dasd':
        #     requires 'volume_id' for both DPM and non-DPM
        # boot_method == 'ftp':
        #   - DPM requires uri to be complete ftp/sftp INS file location
        #   - non-DPM not allowed
        # boot_method == 'custom':
        #   - DPM passes through all 'boot-' parameters and allows 'secure-boot'
        #   - non-DPM not allowed
        #
        # #### VM ####
        #
        # boot_method == 'cms':
        #   cms_options: string, default ''
        # boot_method == 'volume':
        #   volume_type == 'fcp':
        #     - requires 'fcp_adapter', 'wwpn', 'lun'

    # __init__()

    def _run_zvm_logon(self, hyp_session: ZvmSession):
        """Run z/VM logon script"""
        logon_arguments = {
            'guest_name': self._guest.guest_name,
            **self._guest.credentials
        }
        result = hyp_session.logon(logon_arguments)

        if result != 'ok':
            raise RuntimeError("Logon failed")

        if self._parameters['boot_method'] == 'cms':
            result = hyp_session.ipl_cms(
                self._parameters.get('cms_options', ''))
        elif self._parameters['boot_method'] == 'volume':
            result = hyp_session.ipl_from_volume(
                self._parameters['boot_volume'])

        if result != 'ok':
            raise RuntimeError("IPL failed")
        # logoff (disconnect preserving guest state)
        hyp_session.logoff()
    # _run_zvm_logon()

    def perform(self, hyp_session):
        """Perform the action"""
        logger.info("Poweron action on %s", repr(self._guest))
        if isinstance(hyp_session, HmcSession):
            hyp_session.start(self._guest, self._parameters)
        elif isinstance(hyp_session, ZvmSession):
            self._run_zvm_logon(hyp_session)
    # perform()
# PoweronAction


class PoweroffAction:
    """Power off a machine"""

    def __init__(self, guest, parameters=None) -> None:
        """Initialize action"""
        self._guest = guest
        self._parameters = parameters
    # __init__()

    def _run_zvm_reset(self, hyp_session: ZvmSession):
        """Logon and then reset"""
        logon_arguments = {
            'guest_name': self._guest.guest_name,
            **self._guest.credentials
        }
        result = hyp_session.logon(logon_arguments)

        if result != 'ok':
            raise RuntimeError("Logon failed")

        hyp_session.reset()
        hyp_session.logoff(leave_running=False)
    # _run_zvm_reset()

    def perform(self, hyp_session):
        """Perform the action"""
        logger.info("Poweroff action on %s", repr(self._guest))
        if isinstance(hyp_session, HmcSession):
            hyp_session.stop(self._guest)
            if self._parameters and self._parameters.get('deactivate', False):
                hyp_session.deactivate(self._guest)
        elif isinstance(hyp_session, ZvmSession):
            self._run_zvm_reset(hyp_session)
    # perform()
# PoweroffAction
