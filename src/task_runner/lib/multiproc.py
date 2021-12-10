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
Multiprocess Environment

Creates task runners as single processes
"""

#
# IMPORTS
#
import dataclasses
import json
import logging
import os
import secrets

from enum import Enum
from datetime import datetime
from multiprocessing import ProcessError
from signal import SIGTERM

import jsonschema

from .runner import TaskRunner, RunnerExitCode, RESULT_SCHEMA
from .task import Task

#
# CONSTANTS AND DEFINITIONS
#
# local timezone from process perspective
LOCAL_TIMEZONE = datetime.now().astimezone().tzinfo

# maximum name length for a custom working directory
MAX_WORKDIR_NAME_LENGTH = 16

# exception text for invalid work directory
ERR_INVALID_WORK_DIR = f"""Work directory should be strictly alphanumeric
and not longer than {MAX_WORKDIR_NAME_LENGTH} characters"""

# invalid PID indicator
PROCESS_INVALID_PID = -1

#
# CODE
#


class ProcessState(Enum):
    """Possible process states"""
    # entry and environment created:
    CREATED = 'created'
    # process started, not cancelled or otherwise changed
    RUNNING = 'running'
    # stop signal sent, not stopped yet
    STOPPING = 'stopping'
    # confirmed process exit (whether normal, aborted or cancelled)
    EXITED = 'exited'
    # process not found, but no exit confirmation
    LOST = 'lost'

    def __str__(self) -> str:
        """Convert to string"""
        return self.value
    # __str__

# ProcessState


# pylint:disable=too-many-instance-attributes
@dataclasses.dataclass
class ProcessEntry:
    """Describe a process in MultiprocessEnvironment"""
    process: TaskRunner
    work_dir: str
    task_id: str
    task_data: Task
    process_id: int = PROCESS_INVALID_PID
    state: ProcessState = ProcessState.CREATED
    exit_code: RunnerExitCode = RunnerExitCode.UNDETERMINED
    started: datetime = datetime.now(LOCAL_TIMEZONE)
    exited: datetime = datetime(2099, 1, 1, tzinfo=LOCAL_TIMEZONE)
    last_update: datetime = datetime.now(LOCAL_TIMEZONE)

    def _update_online(self):
        """
        Update process status when the process is a valid object
        """
        if self.state == ProcessState.CREATED:
            if self.process.is_alive():
                self.state = ProcessState.RUNNING
                self.last_update = datetime.now(LOCAL_TIMEZONE)
            return

        if self.state != ProcessState.EXITED:
            if not self.process.is_alive():
                self.state = ProcessState.EXITED

                # exit code can be mostly anything, so we don't really check it
                # or try to cast
                self.exit_code = self.process.exitcode
                self.process_id = PROCESS_INVALID_PID
                # registered exit time, may have to be read from work directory
                self.last_update = datetime.now(LOCAL_TIMEZONE)
                self.exited = datetime.now(LOCAL_TIMEZONE)
    # _update_online()

    def _update_offline(self):
        """
        Update process status when there is no process object,
        only working directory
        """
        result_file_path = os.path.join(
            self.work_dir, f'{self.task_id}.result')
        try:
            with open(result_file_path, "rt", encoding='utf-8') as result_file:
                status = json.load(result_file)
        except FileNotFoundError:
            # there is no result file in created state,
            # but the process is not lost yet - just not started
            if self.state != ProcessState.CREATED:
                self.state = ProcessState.LOST
            self.exit_code = RunnerExitCode.UNDETERMINED
            return
        except json.JSONDecodeError:
            self.state = ProcessState.LOST
            self.exit_code = RunnerExitCode.UNDETERMINED
            return

        try:
            jsonschema.validate(status, RESULT_SCHEMA)
        except jsonschema.ValidationError:
            self.state = ProcessState.LOST
            self.exit_code = RunnerExitCode.UNDETERMINED
            return

        if self.task_id != status['task_id']:
            self.state = ProcessState.LOST
            self.exit_code = RunnerExitCode.UNDETERMINED
            return

        self.process_id = status['process_id']
        self.state = ProcessState.RUNNING
        self.last_update = datetime.fromisoformat(status['updated_at'])
        self.started = datetime.fromisoformat(status['started_at'])
        if 'finished_at' in status:
            self.state = ProcessState.EXITED
            self.exited = datetime.fromisoformat(status['finished_at'])
            self.exit_code = RunnerExitCode(status['exit_code'])

    # _update_offline()

    def update(self):
        """Update process status"""
        # we'll be really careful here and pretend that process may also
        # be empty, as if the entry is recovered from old working directory
        if self.process:
            self._update_online()
        else:
            self._update_offline()
    # update()
# ProcessEntry


@dataclasses.dataclass
class EnvParameters:
    """
    Task environment parameters

    Each task may (and should) have a unique running environment, indicated
    by parameters in this class.
    """
    task_id: str = ''
    work_dir: str = ''
# EnvParameters


class MultiprocessEnvironment:
    """Run a task in a thread"""

    def __init__(self, work_dir_path: str, allow_arbitrary_paths: bool) -> None:
        """
        Initialize environment structures

        Args:
            workdir_path: path to a directory that will contain work directories
                for started tasks
            allow_arbitrary_paths: when True, task can be run in any directory
                that is specified in environment parameters (without checks)
        """
        # task id to ProcessEntry
        self._processes = {}

        self._work_dir_path = work_dir_path

        self._allow_arbitrary_paths = allow_arbitrary_paths

        self._logger = logging.getLogger('env-multiproc')
    # __init__()

    @staticmethod
    def is_path_safe(path: str) -> bool:
        """Check if the path is ok to create and use"""
        return (len(path) <= MAX_WORKDIR_NAME_LENGTH
                and path.isalnum())
    # is_path_safe()

    def _create_unique_task_id(self) -> str:
        """Create unique task ID"""
        while True:
            task_id = secrets.token_hex(4)
            if not task_id in self._processes:
                return task_id
    # _create_unique_task_id()

    def get_active_tasks(self) -> "list[ProcessEntry]":
        """Get active task list"""
        return [entry for entry in self._processes.values()
                if entry.state not in (ProcessState.EXITED, ProcessState.LOST)]
    # get_active_tasks()

    def get_all_tasks(self) -> "list[ProcessEntry]":
        """Get list of all tasks"""
        return self._processes.values()
    # get_all_tasks()

    def get_task_data(self, task_id) -> ProcessEntry:
        """Get raw task information"""
        return self._processes.get(task_id)
    # get_task_data()

    def register_task(self, task: Task, env_parameters: EnvParameters = None):
        """
        Register a task for further processing

        Args:
            task: a task to be run
            env_parameters: additional parameters to process environment

        Returns:
            ProcessEntry: descriptor

        Raises:
            ValueError: unacceptable working directory specified
            other OS exceptions: work directory could not be created
        """
        #
        # Prepare task environment
        #

        # ensure default value
        if env_parameters is None:
            env_parameters = EnvParameters()

        if not env_parameters.task_id:
            # no assigned task id - create some
            task_id = self._create_unique_task_id()
        else:
            task_id = str(env_parameters.task_id)

        if not env_parameters.work_dir:
            # no preference set for work_dir - create a new one

            if (MultiprocessEnvironment.is_path_safe(task_id)
                    or not env_parameters.task_id):
                # workdir from task id; either the requested id is valid or
                # a generated id is used - either way it is ok to use it in
                # work dir
                work_dir = f'task-{task_id}'
            else:
                # there is a task id, but we don't want to create
                # arbitrarily named directories, so generate some random name
                work_dir = f'task-{secrets.token_hex(6)}'

        elif (self._allow_arbitrary_paths or
              MultiprocessEnvironment.is_path_safe(env_parameters.work_dir)):
            work_dir = env_parameters.work_dir
        else:
            # disallow invalid input
            raise ValueError(ERR_INVALID_WORK_DIR)

        # we now have a work_dir, whether set or generated
        work_dir = os.path.join(self._work_dir_path, work_dir)
        try:
            os.mkdir(work_dir)
        except FileExistsError:
            # ignore if exists - we may have been given a valid path already
            pass

        # register within internal structure
        entry = ProcessEntry(None, work_dir, task_id, task)

        self._processes[task_id] = entry
        return entry
    # register_task()

    def start_task(self, task_id: str):
        """
        Create a new process and start task in it

        Returns:
            ProcessEntry: process descriptor

        Raises:
            ProcessError: task could not be started
        """
        task_entry = self._processes.get(task_id)
        if task_entry is None:
            return None

        # create, but don't start a task runner
        process = TaskRunner(task_entry.task_data, task_entry.work_dir,
                             task_entry.task_id)

        try:
            process.start()
        except ProcessError:
            self._processes[task_id].state = ProcessState.EXITED
            self._processes[task_id].exited = datetime.now(LOCAL_TIMEZONE)
            # re-raising here is bad, because we don't get the chance to
            # report a task ID
            raise

        self._processes[task_id].process = process
        self._processes[task_id].state = ProcessState.RUNNING
        return self._processes[task_id]
    # start_task()

    def stop_task(self, task_id):
        """Stop a task by stopping an associated process"""
        if not task_id in self._processes:
            return None

        proc_entry: ProcessEntry = self._processes[task_id]
        if proc_entry.state not in (ProcessState.EXITED, ProcessState.LOST):
            proc_entry.state = ProcessState.STOPPING
            if proc_entry.process:
                # we have an active process object
                proc_entry.process.terminate()
            elif proc_entry.process_id != PROCESS_INVALID_PID:
                # we don't have an object, but have a pid
                os.kill(proc_entry.process_id, SIGTERM)
            else:
                # process is in fact lost or not created yet. We cannot do much
                # at this point, state is already set to non-running.
                # If anyone cares, they will call ProcessEntry.update()
                self._logger.warning(
                    'Could not stop task %s, pid %d',
                    task_id, proc_entry.process_id)

        return self._processes[task_id]
    # stop_task()

    def unregister_task(self, task_id):
        """Remove task from known list"""
        if not task_id in self._processes:
            return False

        proc_entry: ProcessEntry = self._processes[task_id]
        if not proc_entry.state in (ProcessState.EXITED, ProcessState.LOST):
            # why remove an active process?
            pass

        self._processes.pop(task_id)
        return True
    # unregister_task()

    def wait_completion(self, task_id):
        """Wait until task completion (blocking)"""
        if not task_id in self._processes:
            return False

        proc_entry: ProcessEntry = self._processes[task_id]
        proc_entry.process.join()
        proc_entry.update()
        return proc_entry.exit_code
    # wait_completion()

# MultiprocessEnvironment
