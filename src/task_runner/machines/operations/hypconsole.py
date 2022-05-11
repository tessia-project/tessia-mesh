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
Hypervisor Console

A basic read/write console for use with hypervisors
"""

#
# IMPORTS
#

import abc
import logging


#
# CONSTANTS AND DEFINITIONS
#


#
# CODE
#
logger = logging.getLogger(__name__)


class HypStream:
    """
    Interface for hypervisors to implement for reading the console
    """
    @abc.abstractmethod
    def read(self, *, timeout, **kwargs) -> list:
        """
        Read updates from the console as a list of strings

        Args:
            timeout (float): Timeout in seconds
            **kwargs: Additional arguments

        Returns:
            list: List of strings
        """
    # read()

    @abc.abstractmethod
    def write(self, data: str, **kwargs) -> None:
        """
        Write data to the console

        Args:
            data (str): Data to write
            **kwargs: Additional arguments
        """
    # write()
# HypStream
