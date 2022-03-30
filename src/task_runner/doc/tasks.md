<!--
Copyright 2022 IBM Corp.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Tasks provided by Task Runner

Tasks provided by Task Runner are defined by machines in the `machines` subdirectory.

## Power manager

Power manager works with the hypervisor to perform guest start, stop and other operations.
A single task may contain several actions, which will be executed sequentially:

```
"machine": "powerman",
"parameters": {
    "targets": [
        // action 1
        {
            "action": "start",
            "system": {...},
            "hypervisor": {...},
            "parameters": {...}
        },
        // action 2
        {
            "action": "stop",
            "system": {...},
            "hypervisor": {...},
            "parameters": {...}
        },
    ]
}
```

See also an example of [Power manager task](./sample_powerman.json).

Each action is a dictinary with the following keys:
- `action`: action to perform
- `system`: system to perform the action on
- `hypervisor`: hypervisor that controls the system
- `parameters`: parameters for the action

Different hypervisors and operations have different parameters.

### Hypervisor parameters

To operate on HMC following `hypervisor` properties are available:
- `type`: "cpc" (required)
- `hostname`: hostname of the HMC (required)
- `credentials`: credentials for the HMC (required), descibed by:
    - `username`: username
    - `password`: password
- `connection_options`: connection options for the HMC, described by:
    - `port`: port number
    - `connect_timeout`: timeout to connect to the HMC
    - `status_timeout`: timeout waiting for status changes
    - `operation_timeout`: timeout waiting for completion of an operation
    - `verify_certificate`: verify TLS certificates

LPAR guests are described with the following `system` properties:
- `cpc`: CPC name (required)
- `partition_name`: name of the partition (required)

To operate on z/VM following `hypervisor` properties are available:
- `type`: "zvm" (required)
- `hostname`: hostname of the z/VM (required)

z/VM guests are described with the following `system` properties:
- `guest_name`: guest name (required)
- `credentials`: credentials for the guest (required), descibed by:
    - `userid`: user ID
    - `password`: password
    - `logon_by`: (optional) a different user id to logon with


### Start action parameters

`"action": "start"`

Activates and loads an LPAR guest; IPLs a z/VM guest.

#### For LPAR:

To boot last location indicate empty parameter set:
```
"parameters": {}
```

Otherwise, depending on `boot_method`:
- `"boot_method": "volume"`:
    Load from volume. `volume_type` may be one of ( `fcp`, `dasd`)
    
    With `"volume_type": "fcp"`:
    - In DPM mode specify `uuid` to have a storage group match
    - In classic mode specify `fcp_adapter`, `wwpn`, `lun`
    
    For secure boot indicate `"secure_boot": true`
    
    With `"volume_type": "dasd"`:
    - Specify `volume_id` in both DPM and non-DPM modes
- `"boot_method": "ftp"`:
    Only allowed in DPM mode. 
    
    Set `uri` to be complete ftp/sftp INS file location
- `"boot_method": "custom"`:
    Only allowed in DPM mode.
    
    All parameters starting with 'boot-' or 'secure-boot' are passed through to the HMC.


#### For z/VM:

Depending on `boot_method`:
- `boot_method == 'cms'`:
  Logon to the guest and IPL CMS
  For additional CMS parameters specify `"cms_options"` string.

- `"boot_method": "volume"`:
    Load from volume or other device.
    
    With `"volume_type": "fcp"`:
    - specify `fcp_adapter`, `wwpn`, `lun`
    
    Any other option for `"volume_type"` (e.g. `"dasd"`, `"mdisk"` etc.) is considered an IPL-able device.
    - specify `volume_id` for the device to IPL from.

Task runner will disconnect from the guest, leaving it running.

### Stop action parameters

`"action": "stop"`

Stops or deactivates an LPAR, clears and logs off z/VM guest.

No parameters are provided.

## Echo

This machine performs simple script to test its operations.
Script is a list of statements; each statement can be
    - system allocation (USE resource)
    - message to be echoed (ECHO line)
    - sleep (SLEEP time in seconds)
    - log (LOG level message)

Example:
```
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
```

See also an example of [Echo machine task](./sample_powerman.json).

