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
Echo Machine
"""

#
# IMPORTS
#
import logging
from time import sleep

from task_runner.lib.task import Task


#
# CONSTANTS AND DEFINITIONS
#

LOG_LEVELS = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")


#
# CODE
#


class EchoMachine:
    """A simple machine that echoes messages"""

    @staticmethod
    def run(task: Task):
        """Thread entry point"""
        script = task.parameters
        instance = EchoMachine(script)
        instance.start()
    # run()

    @staticmethod
    def validate(task: Task):
        """Parse parameters and perform as many static checks as possible"""
        script = task.parameters
        instance = EchoMachine(script)
        instance._parse_script()    # pylint:disable=protected-access
    # validate()

    def __init__(self, script) -> None:
        """Initialize machine instance"""
        self._script = script

        self._logger = None
    # __init__()

    # pylint:disable=too-many-branches
    # Parsing has many ways to go wrong
    def _parse_script(self):
        """
        Parse script for correctness

        Script is a list of statements; each statement can be
        - system allocation (USE resource)
        - message to be echoed (ECHO line)
        - sleep (SLEEP time in seconds)
        - log (LOG level message)
        Example:
        USE SHARED lpar01
        USE EXCLUSIVE guest01 guest02
        ECHO Hello world!
        LOG INFO Now sleeping
        SLEEP 50
        ECHO Test ended.
        CLEANUP
        ECHO cleanup started
        SLEEP 2
        ECHO cleanup done

        Returns:
            dict: containing resources allocated and list of commands
                  to be executed

        Raises:
            SyntaxError: if content is in wrong format
        """

        ret = {
            'resources': {'shared': [], 'exclusive': []},
            'commands': [],
            'cleanup_commands': [],
        }

        cleanup = False
        commands = ret['commands']

        for index, line in enumerate(self._script):
            fields = line.split('#', 1)[0].split()

            # empty line or comments: skip it
            if not fields:
                continue

            if fields[0].lower() == 'cleanup':
                cleanup = True
                commands = ret['cleanup_commands']

            elif fields[0].lower() == 'use':
                if cleanup:
                    raise SyntaxError('USE is not allowed in cleanup section',
                                      ('EchoMachine', index+1, 1, line[:20]))

                # syntax check
                if len(fields) < 3:
                    raise SyntaxError(
                        f'USE expects 2 arguments ({len(fields)-1} provided)',
                        ('EchoMachine', index+1, 4, line[:20]))

                try:
                    ret['resources'][fields[1].lower()].extend(fields[2:])
                except KeyError:
                    raise SyntaxError(
                        'USE mode should be "shared" or "exclusive" '
                        f'({fields[1].lower()} found)',
                        ('EchoMachine', index+1, 4, line[:20])) from None

            elif fields[0].lower() == 'echo':
                # syntax check
                if len(fields) < 2:
                    raise SyntaxError(
                        'ECHO expects an argument to output',
                        ('EchoMachine', index+1, 5, line[:20]))

                commands.append(['echo', ' '.join(fields[1:])])

            elif fields[0].lower() == 'sleep':
                if len(fields) != 2:
                    raise SyntaxError(
                        f'SLEEP expects 1 argument ({len(fields)-1} provided)',
                        ('EchoMachine', index+1, 6, line[:20]))
                try:
                    seconds = float(fields[1])
                except ValueError:
                    raise SyntaxError(
                        'SLEEP argument must be a number',
                        ('EchoMachine', index+1, 6, line[:20])) from None

                commands.append(['sleep', seconds])

            elif fields[0].lower() == 'return':
                if len(fields) != 2:
                    raise SyntaxError(
                        f'RETURN expects 1 argument ({len(fields)-1} provided)',
                        ('EchoMachine', index+1, 7, line[:20]))
                try:
                    ret_value = int(fields[1])
                except ValueError:
                    raise SyntaxError(
                        'RETURN argument must be an integer',
                        ('EchoMachine', index+1, 7, line[:20])) from None

                commands.append(['return', ret_value])

            elif fields[0].lower() == 'raise':
                commands.append(['raise'])

            elif fields[0].lower() == 'log':
                if len(fields) < 3:
                    raise SyntaxError(
                        f'LOG expects 2 arguments ({len(fields)-1} provided)',
                        ('EchoMachine', index+1, 4, line[:20]))

                if fields[1].upper() not in LOG_LEVELS:
                    raise SyntaxError(
                        f'LOG level must be one of ({", ".join(LOG_LEVELS)})',
                        ('EchoMachine', index+1, 4, line[:20]))

                commands.append(
                    ['log', fields[1].upper(), ' '.join(fields[2:])])

            else:
                raise SyntaxError(f'Invalid command {fields[0]}',
                                  ('EchoMachine', index+1, 1, line[:20]))

        return ret
    # _parse_script()

    def start(self):
        """Run the machine"""
        self._logger = logging.getLogger('sample-task')
        self._logger.info("Echo machine started")

        processed = self._parse_script()
        for cmd in processed['commands']:
            if cmd[0] == 'echo':
                print(cmd[1])
            elif cmd[0] == 'sleep':
                sleep(cmd[1])
            elif cmd[0] == 'return':
                return cmd[1]
            elif cmd[0] == 'raise':
                raise RuntimeError
            elif cmd[0] == 'log':
                if cmd[1] == 'DEBUG':
                    self._logger.debug(cmd[2])
                elif cmd[1] == 'INFO':
                    self._logger.info(cmd[2])
                elif cmd[1] == 'WARNING':
                    self._logger.warning(cmd[2])
                elif cmd[1] == 'ERROR':
                    self._logger.error(cmd[2])
                elif cmd[1] == 'CRITICAL':
                    self._logger.critical(cmd[2])

        return 0
    # start()

# EchoMachine
