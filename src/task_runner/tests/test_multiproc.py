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

# pylint:disable=redefined-outer-name

"""
Multiprocess Environment unit tests
"""

#
# IMPORTS
#

import json
import os.path
import pytest

from task_runner.lib.multiproc import MultiprocessEnvironment
from task_runner.lib.task import task_from_dict

#
# CONSTANTS AND DEFINITIONS
#


#
# CODE
#

@pytest.fixture
def mpenv(tmp_path):
    """Create Multiprocess Environment"""
    env = MultiprocessEnvironment(tmp_path, False)
    yield env
# mpenv()


def test_task_results_are_created(mpenv: MultiprocessEnvironment):
    """Verify that task results are created"""
    task = task_from_dict({
        'machine': 'echo', 'parameters': [
            'echo Machine starting',
            'sleep 0.2',
            'echo Machine stopping'
        ]})
    entry = mpenv.register_task(task)
    mpenv.start_task(entry.task_id)
    mpenv.wait_completion(entry.task_id)

    with open(os.path.join(entry.work_dir, f'{entry.task_id}.result'),
              'rt', encoding='utf-8') as result_file:
        result = json.load(result_file)

    assert result['task_id'] == entry.task_id
    assert result['exit_code'] == 0
# test_task_results_are_created()
