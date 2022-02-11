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
Power Manager Machine

The machine is responsible for hypervisor actions on targets,
such as poweroon, poweroff, define and erase.

Machine accepts a list of actions to perform along with the target description.
"""


#
# IMPORTS
#
import logging

from task_runner.lib.task import Task
from task_runner.machines.operations.zvm import ZvmGuest, ZvmHypervisor, ZvmSession
from .actions import PoweronAction, PoweroffAction
from ..operations.hmc import HmcSession, CpcPartition, CpcHypervisor

#
# CONSTANTS AND DEFINITIONS
#


#
# CODE
#


class PowerManagerMachine:
    """A machine that can turn on and off guests"""

    @ staticmethod
    def run(task: Task):
        """Thread entry point"""
        # validate and throw
        parameters = task.parameters
        instance = PowerManagerMachine(parameters)
        instance.start()
    # run()

    @ staticmethod
    def validate(task: Task):
        """
        Parse parameters and perform as many static checks as possible

        Args:
            task (Task): incoming task

        Raises:
            ValueError: static validation failed
        """
        try:
            PowerManagerMachine(task.parameters)
        except (RuntimeError, ValueError, KeyError) as exc:
            raise ValueError("Validation failed") from exc
    # validate()

    @staticmethod
    def create_model(targets: list):
        """
        Convert to internal model

        The model is a list of tuples (action, hypervisor, guest),
        where
        """
        model = []
        for action in targets:
            if action['hypervisor']['type'] == 'cpc':
                hypervisor = CpcHypervisor(
                    action['hypervisor']['hostname'],
                    action['hypervisor']['credentials'],
                    action['hypervisor'].get('connection_options', {}))
            elif action['hypervisor']['type'] == 'zvm':
                hypervisor = ZvmHypervisor(
                    action['hypervisor']['hostname'],
                    action['hypervisor'].get('connection_options', {})
                )
            else:
                hypervisor = None

            if all(prop in action['system']
                   for prop in ('cpc', 'partition_name')):
                guest = CpcPartition(
                    action['system']['cpc'],
                    action['system']['partition_name'])
            elif all(prop in action['system']
                     for prop in ('guest_name', 'credentials')):
                guest = ZvmGuest(action['system']['guest_name'],
                                 action['system']['credentials'])
            else:
                guest = None

            if action['action'] == 'start':
                action = PoweronAction(guest, action.get('parameters'))
            elif action['action'] == 'stop':
                action = PoweroffAction(guest)
            else:
                action = None

            if action:
                model.append((action, hypervisor))
        return model
    # create_model()

    def __init__(self, parameters) -> None:
        """Initialize machine instance"""
        self._model = self.create_model(parameters['targets'])

        self._logger = None
    # __init__()

    def start(self):
        """Run the machine"""
        self._logger = logging.getLogger('power_manager')
        self._logger.info("Power Manager machine started")
        self._logger.info("%d actions to perform", len(self._model))

        # we might want to group actions per hypervisor
        # to save on logon/logoff
        hyp_session = None

        for index, (action, hypervisor) in enumerate(self._model, start=1):
            self._logger.info("Action %d / %d", index, len(self._model))

            if (hyp_session is None or not hyp_session.compatible(hypervisor)):
                # disconnect
                if hyp_session is not None:
                    hyp_session.disconnect()

                # create new session
                if isinstance(hypervisor, CpcHypervisor):
                    hyp_session = HmcSession(hypervisor)
                    hyp_session.connect()
                elif isinstance(hypervisor, ZvmHypervisor):
                    hyp_session = ZvmSession(hypervisor)
                    hyp_session.connect()

            action.perform(hyp_session)
        # finalize
        if hyp_session is not None:
            hyp_session.disconnect()
    # start()
