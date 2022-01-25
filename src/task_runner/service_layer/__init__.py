# Copyright 2021, 2022 IBM Corp.
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
Service layer for communication between API and library code
"""

#
# IMPORTS
#
import asyncio
from dataclasses import dataclass
from datetime import datetime
import logging
import multiprocessing
from os import makedirs

from ..lib.task import task_from_dict
from ..lib.multiproc import MultiprocessEnvironment, ProcessEntry, ProcessState

#
# CONSTANTS AND DEFINITIONS
#
WORK_DIR = '/var/lib/tessia-mesh/task_runner'

#
# CODE
#


class NotFound(ValueError):
    """Task is not present in service layer"""
# NotFound


@dataclass
class TaskDescription:
    """Service Layer description for a task"""
    task_id: str
    state: str
    started: datetime
    exited: datetime = None

    @staticmethod
    def from_multiprocess(data: ProcessEntry):
        """Create description from MultiprocessEnvironment entry"""
        result = TaskDescription(
            data.task_id, str(data.state), data.started, None
        )
        if data.state == ProcessState.EXITED:
            result.exited = data.exited

        return result
    # from_multiprocess()
# TaskDescription


class ServiceLayer:
    """Encapsulate API and library interaction"""

    def __init__(self) -> None:
        """Initialize service layer"""
        # define work directory for environments
        makedirs(WORK_DIR, exist_ok=True)

        # tasks environment
        self._mp_env = MultiprocessEnvironment(WORK_DIR, False)
    # __init__()

    def add_task(self, task_dict) -> TaskDescription:
        """
        Starts a new task. May raise underlying exceptions.

        May raise underlying expections (ValueError, ProcessError etc.)
        """
        task = task_from_dict(task_dict)
        task_entry = self._mp_env.register_task(task)
        task_entry = self._mp_env.start_task(task_entry.task_id)

        return TaskDescription.from_multiprocess(task_entry)
    # add_task()

    def get_task_status(self, task_id) -> TaskDescription:
        """
        Retrieve status of a task

        Raises:
            NotFound: task not found
        """
        task_entry = self._mp_env.get_task_data(task_id)
        if not task_entry:
            raise NotFound()

        return TaskDescription.from_multiprocess(task_entry)
    # get_task_status()

    def list_tasks(self) -> 'list[TaskDescription]':
        """
        Return list of all known tasks
        """
        task_entries = self._mp_env.get_all_tasks()

        return [TaskDescription.from_multiprocess(entry)
                for entry in task_entries]
    # list_tasks()

    def stop_task(self, task_id) -> TaskDescription:
        """
        Stop a task

        Raises:
            NotFound: task not found
        """
        task_entry = self._mp_env.stop_task(task_id)
        if not task_entry:
            raise NotFound()

        return TaskDescription.from_multiprocess(task_entry)
    # stop()

    def forget_task(self, task_id) -> bool:
        """
        Forget about a task

        Returns:
            bool: successful result

        Raises:
            NotFound: task not found
        """
        result = self._mp_env.unregister_task(task_id)
        if not result:
            raise NotFound()

        return True
    # stop()

# ServiceLayer


class ServiceLayerWorker:  # pylint:disable=too-few-public-methods
    """Maintenance worker"""

    def __init__(self, service_layer: ServiceLayer) -> None:
        """Initialize worker"""
        self._service_layer = service_layer
    # __init__()

    async def update_known_tasks(self):
        """Update status for known tasks"""
        # Service worker has to ask every environment in the service layer,
        # but there can be a better way than to go to private class members
        # pylint:disable=protected-access
        task_list = self._service_layer._mp_env.get_active_tasks()

        logger = logging.getLogger('service-layer')
        for task in task_list:
            try:
                task.update()
            except Exception as exc:    # pylint:disable=broad-except
                # don't want a worker to halt because of an uncaught exception
                logger.warning('Task update failed, task_id %s',
                               task.task_id, exc_info=exc)
            await asyncio.sleep(0)

        # workaround for multiprocess leaving zombies:
        # this call has a side effect of joining all completed tasks
        multiprocessing.active_children()
    # update_known_tasks()

# ServiceLayerWorker
