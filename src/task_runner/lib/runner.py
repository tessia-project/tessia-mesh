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
Task Runner

A wrapper implemented as a Process subclass for a task.
A task is run in a separate thread inside the process; main thread continuously
monitors its status, reacts to signals and provides updates.
"""

#
# IMPORTS
#
from datetime import datetime
from enum import Enum
from multiprocessing import Process
from queue import Queue
from threading import Thread

import json
import logging
import os
import signal
import sys
import threading
import time

from .task import task_from_dict
from ..machines import EchoMachine, PowerManagerMachine

#
# CONSTANTS AND DEFINITIONS
#

# Cancel signals we can handle
CANCEL_SIGNALS = (
    signal.SIGTERM,
    signal.SIGHUP,
    signal.SIGINT
)

# Watchdog will print messages this often (seconds)
WATCHDOG_INTERVAL = 60.0

# Log format string
LOG_FORMAT_STRING = ('[%(asctime)s] %(levelname)s'
                     ' [%(name)s.%(funcName)s:%(lineno)d] %(message)s')


class RunnerExitCode(Enum):
    """Exit status codes"""
    SUCCESS = 0
    CANCELED = -1
    TIMEOUT = -2
    EXCEPTION = -3
    UNDETERMINED = -99

    def __int__(self):
        """Convert to integer"""
        return self.value
    # __int__()
# RunnerExitCode


RESULT_SCHEMA = {
    '$schema': 'https://json-schema.org/draft/2020-12/schema',
    'type': 'object',
    'title': 'Task result schema',
    '$defs': {},
    'properties': {
        'task_id': {
            'type': 'string'
        },
        'process_id': {
            'type': 'integer'
        },
        'started_at': {
            'type': 'string'
        },
        'updated_at': {
            'type': 'string'
        },
        'finished_at': {
            'type': 'string'
        },
        'exit_code': {
            'type': 'integer'
        },
        'status': {
            # unspecified, task-dependent
        }
    },
    'required': ['task_id', 'process_id', 'started_at', 'updated_at'],
    'additionalProperties': False,
}

# local timezone from process perspective
LOCAL_TIMEZONE = datetime.now().astimezone().tzinfo

#
# CODE
#

# pylint:disable=too-few-public-methods


class NotImplementedMachine:
    """A task for test purposes"""
    @staticmethod
    def run(task):
        """Run task"""
        raise RuntimeError(f'Machine {task.machine} not impelmented')
    # run()
# NotImplementedMachine


class RunnerThread(Thread):
    """Exception-handling thread"""

    def __init__(self, exc_store: Queue, *args, **kwargs) -> None:
        """
        Init with exception storage

        Args:
            exc_store: a thread-safe storage for exception information
            args (Iterable): arguments to thread main function
        """
        super().__init__(*args, **kwargs)
        self.exc_store = exc_store
    # __init__()

    def run(self):
        """
        Run with exception handling
        """
        try:
            super().run()
        except Exception:   # pylint:disable=broad-except
            # Catch any exception and pass it further
            self.exc_store.put(sys.exc_info())
    # run()
# RunnerThread


class TaskRunner(Process):
    """A process to run a task"""

    def __init__(self, task, work_dir: str, identifier: str,
                 *args, **kwargs) -> None:
        """
        Initialize the process

        Args:
            task: state machine description
            work_dir: working directory for the process
            identifier: results file identifier
        """
        super().__init__(args=args, kwargs=kwargs)

        self._task = task
        self._work_dir = work_dir
        self._identifier = identifier

        # published at runtime
        self._logger = None
        self._stop_event = None
        self._start_time_str = ''
    # __init__()

    def run(self):
        """Process main loop - this is the entry point"""
        # setworking directory
        os.chdir(self._work_dir)

        logging.basicConfig(filename='output.log', level=logging.DEBUG,
                            format=LOG_FORMAT_STRING,
                            datefmt=r'%Y-%m-%d %H:%M:%S')

        self._logger = logging.getLogger('task_runner')

        # create an internal buffer for storing other thread exception state
        exception_store = Queue()

        # a signalling
        self._stop_event = threading.Event()
        set_cancel_signal_handler(self._stop_by_signal)

        # record start time
        self._start_time_str = datetime.now(LOCAL_TIMEZONE).isoformat()

        self._save_status()

        self._logger.info("Runner started")
        watchdog_loop_time = time.monotonic()

        target_cls = {
            'echo': EchoMachine,
            'powerman': PowerManagerMachine
        }.get(self._task.machine, NotImplementedMachine)

        # thread with the machine
        # Note that it is set as "daemonic" so that the runner could quit
        # when cancelled without waiting on the thread
        run_thread = RunnerThread(
            exception_store, target=target_cls.run, args=(self._task,),
            daemon=True)
        run_thread.start()

        # wait for either stop or completion
        while not self._stop_event.is_set():
            run_thread.join(timeout=0.1)
            if not run_thread.is_alive():
                break

            # watchdog message
            watchdog_current_time = time.monotonic()
            if watchdog_current_time - watchdog_loop_time > WATCHDOG_INTERVAL:
                self._logger.info("Still running")
                watchdog_loop_time = watchdog_current_time
                self._save_status()

        if run_thread.is_alive():
            self._logger.info("Runner cancelled")
            self._exit(RunnerExitCode.CANCELED)
        elif not exception_store.empty():
            self._logger.info(
                "Runner aborted", exc_info=exception_store.get())
            self._exit(RunnerExitCode.EXCEPTION)

        self._logger.info("Runner completed")
        self._exit(RunnerExitCode.SUCCESS)
    # run()

    def _save_status(self):
        """Write current status"""
        with open(f'{self._identifier}.result',
                  'wt', encoding='utf-8') as results_file:
            json.dump({
                'task_id': self._identifier,
                'process_id': self.pid,
                'updated_at': datetime.now(LOCAL_TIMEZONE).isoformat(),
                'started_at': self._start_time_str
            }, results_file)
    # _save_status()

    def _exit(self, code):
        """Exit and write status"""
        now = datetime.now(LOCAL_TIMEZONE).isoformat()
        with open(f'{self._identifier}.result',
                  'wt', encoding='utf-8') as results_file:
            json.dump({
                'task_id': self._identifier,
                'process_id': self.pid,
                'updated_at': now,
                'started_at': self._start_time_str,
                'finished_at': now,
                'exit_code': int(code)
            }, results_file)

        sys.exit(int(code))
    # _exit()

    def _stop_by_signal(self, *_args, **_kwargs):
        """Respond to cancel signals by stopping"""
        self._stop_event.set()
    # _stop_by_signal()

# TaskRunner


def set_cancel_signal_handler(handler):
    """
    Set the handler function for all cancellation signals.

    Args:
        handler (function): signal handler, like for signal.signal
    """
    for signal_type in CANCEL_SIGNALS:
        signal.signal(signal_type, handler)
# set_cancel_signal_handler()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit("Usage: python -m runner <task.json>")

    with open(sys.argv[1], "rt", encoding='utf-8') as task_file:
        proc = TaskRunner(
            task_from_dict(json.load(task_file)), '.', 'cli')

    proc.start()
    proc.join()
