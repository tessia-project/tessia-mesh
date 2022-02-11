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

# pylint:disable=redefined-outer-name,no-self-use,unused-argument

"""
Power Manager machine tests
"""

#
# IMPORTS
#
import pytest

from task_runner.lib.task import task_from_dict
from task_runner.machines import PowerManagerMachine
from task_runner.machines.operations import zvm

from .operations.vm_mocks import TerminalMock


#
# CONSTANTS AND DEFINITIONS
#


#
# CODE
#


@pytest.fixture
def mock_zvm(monkeypatch):
    """Substitute Pipe connector with our custom class"""
    monkeypatch.setattr(zvm, 'S3270PipeConnector', TerminalMock)
    zvm.DEFAULT_BEHAVIOUR['command_timeout'] = 1.0


def test_task_schema_start_validation():
    """Check variations on task schema"""
    all_mix = task_from_dict({
        'machine': 'powerman',
        'parameters': {
            'targets': [
                # DASD start
                {
                    "action": "start",
                    "system": {
                        "cpc": "CPC1",
                        "partition_name": "lp1"
                    },
                    "hypervisor": {
                        "type": "cpc",
                        "hostname": "hmc.example.com",
                        "credentials": {
                            "username": "tessia",
                            "password": "test"
                        },
                        "connection_options": {
                            "verify_certificate": False
                        }
                    },
                    "parameters": {
                        "boot_method": "volume",
                        "volume_type": "dasd",
                        "volume_id": "1234"
                    }
                },
                # FCP start
                {
                    "action": "start",
                    "system": {
                        "cpc": "CPC1",
                        "partition_name": "lp1"
                    },
                    "hypervisor": {
                        "type": "cpc",
                        "hostname": "hmc.example.com",
                        "credentials": {
                            "username": "tessia",
                            "password": "test"
                        },
                        "connection_options": {
                            "verify_certificate": False
                        }
                    },
                    "parameters": {
                        "boot_method": "volume",
                        "volume_type": "fcp",
                        "uuid": "1234bcde5678fabc0984"
                    }
                },
                # FTP boot
                {
                    "action": "start",
                    "system": {
                        "cpc": "CPC1",
                        "partition_name": "lp1"
                    },
                    "hypervisor": {
                        "type": "cpc",
                        "hostname": "hmc.example.com",
                        "credentials": {
                            "username": "tessia",
                            "password": "test"
                        },
                        "connection_options": {
                            "verify_certificate": False
                        }
                    },
                    "parameters": {
                        "boot_method": "ftp",
                        "uri": "ftp://user:pass@ftp.example.com/lp1.ins",
                    }
                },
                # DPM boot options pass-through
                {
                    "action": "start",
                    "system": {
                        "cpc": "CPC1",
                        "partition_name": "lp1"
                    },
                    "hypervisor": {
                        "type": "cpc",
                        "hostname": "hmc.example.com",
                        "credentials": {
                            "username": "tessia",
                            "password": "test"
                        },
                        "connection_options": {
                            "verify_certificate": False
                        }
                    },
                    "parameters": {
                        "boot_method": "custom",
                        "boot-device": "removable-media",
                        "boot-removable-media": "removable-media",
                        "boot-removable-media-type": "usb"
                    }
                },

            ]
        }
    })

    assert PowerManagerMachine.validate(all_mix) is None
# test_task_schema_validation()


def test_zvm_actions(mock_zvm):
    """
    Test that z/VM can be IPL'ed into CMS, from DASD and SCSI volume
    Test that z/VM can be powered off
    """

    parameters = {
        'targets': [
            {
                "action": "start",
                "system": {
                    "guest_name": "vm1",
                    "credentials": {
                        "username": "vm1",
                        "password": "example",
                    }
                },
                "hypervisor": {
                    "type": "zvm",
                    "hostname": "zvm.example.com",
                },
                "parameters": {
                    "boot_method": "cms"
                }
            },
            {
                "action": "stop",
                "system": {
                    "guest_name": "vm1",
                    "credentials": {
                        "username": "vm1",
                        "password": "example",
                    }
                },
                "hypervisor": {
                    "type": "zvm",
                    "hostname": "zvm.example.com",
                },
                "parameters": {}
            },
            {
                "action": "start",
                "system": {
                    "guest_name": "vm1",
                    "credentials": {
                        "username": "vm1",
                        "password": "example",
                    }
                },
                "hypervisor": {
                    "type": "zvm",
                    "hostname": "zvm.example.com",
                },
                "parameters": {
                    "boot_method": "volume",
                    "boot_volume": {
                        "volume_type": "fcp",
                        "fcp_adapter": "1926",
                        "wwpn": "500507630b034320",
                        "lun": "4035407400000000"
                    }
                }
            },
        ]
    }
    machine = PowerManagerMachine(parameters)
    machine.start()
