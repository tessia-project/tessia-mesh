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
Hypoervisor session

Keeps a session to the hypervisor for reuse
"""


#
# IMPORTS
#
import logging

from dataclasses import dataclass
from urllib.parse import urlsplit

import zhmcclient

#
# CONSTANTS AND DEFINITIONS
#
DEFAULT_CONNECTION_OPTIONS = {
    'port': zhmcclient.DEFAULT_HMC_PORT,
    'connect_timeout': zhmcclient.DEFAULT_CONNECT_TIMEOUT,
    'status_timeout': zhmcclient.DEFAULT_STATUS_TIMEOUT,
    'operation_timeout': zhmcclient.DEFAULT_OPERATION_TIMEOUT,
    'verify_certificate': True
}


#
# CODE
#
logger = logging.getLogger(__name__)


@dataclass
class CpcHypervisor:
    """HMC hypervisor definition"""
    hostname: str
    credentials: dict
    connection_options: dict

    def __repr__(self) -> str:
        return f'CpcHypervisor({self.hostname})'
# CpcHypervisor


@dataclass
class CpcPartition:
    """A complex name for a partition"""
    cpc: str
    partition_name: str

    def __repr__(self) -> str:
        return f'CpcPartition({self.cpc}, {self.partition_name})'
# CpcPartition


class HmcSession:
    """HMC hypervisor session"""

    def __init__(self, hypervisor: CpcHypervisor) -> None:
        """Initialize hypervisosr"""
        self._hypervisor = hypervisor
        self._connection_options = DEFAULT_CONNECTION_OPTIONS.copy()
        self._connection_options.update(hypervisor.connection_options)

        self._client = None
        self._cache = {}
    # __init__()

    def _find_guest(self, guest: CpcPartition):
        """Find and cache guest object"""
        # check cache
        if partition := self.cache(guest.partition_name):
            return partition

        # find CPC
        cpc: zhmcclient.Cpc = self._client.cpcs.find_by_name(guest.cpc)
        if not cpc:
            raise RuntimeError(f"CPC {guest.cpc} not found")

        # query and cache only interesting properties
        # direct query considerably saves request time
        cpc_props = self._client.session.get(
            f'{cpc.uri}?properties=dpm-enabled')
        if 'dpm-enabled' not in cpc_props:
            cpc_props['dpm-enabled'] = False
        cpc.update_properties_local(cpc_props)

        # find guest
        if cpc.dpm_enabled:
            partition = cpc.partitions.find_by_name(guest.partition_name)
        else:
            partition = cpc.lpars.find_by_name(guest.partition_name)
        if not partition:
            logger.debug("Partition %s on CPC %s not found",
                         guest.partition_name, guest.cpc)
            logger.debug("CPC %s status: %s", guest.cpc, cpc.prop('status'))
            raise RuntimeError("Partition not found")

        # get current partition status
        self._refresh_partition_properties(partition)

        # cache and return
        return self.cache(guest.partition_name, partition)
    # _find_guest()

    def _find_storage_volume(self, guest: CpcPartition, boot_params):
        """
        Find the uri of a storage volume
        """
        partition = self._find_guest(guest)
        if boot_params['volume_type'] == 'fcp':
            sg_type = 'fcp'
            prop_key = 'uuid'
            prop_value = boot_params['uuid']
        elif boot_params['volume_type'] == 'dasd':
            sg_type = 'fc'
            prop_key = 'device-number'
            prop_value = boot_params['volume_id']

        logger.debug("Looking for storage volume object with %s='%s'",
                     prop_key, prop_value)
        # search the corresponding volume in the storage groups attached to the
        # partition
        for sg_uri in partition.get_property('storage-group-uris'):
            sg_obj = self._client.consoles.console.\
                storage_groups.resource_object(sg_uri)
            if sg_obj.get_property('type').lower() != sg_type:
                logger.debug(
                    "Skipping storage group %s, type '%s' (actual) != '%s' "
                    "(expected)", sg_obj.get_property('name'),
                    sg_obj.get_property('type').lower(), sg_type)
                continue
            # find the matching volume
            for sg_vol in sg_obj.storage_volumes.list():
                sg_vol.pull_full_properties()
                try:
                    sg_vol_value = sg_vol.get_property(prop_key)
                except KeyError:
                    continue
                if sg_vol_value.lower() != prop_value.lower():
                    continue
                if sg_vol.get_property('usage') != 'boot':
                    sg_vol.update_properties({'usage': 'boot'})
                return sg_vol.get_property('element-uri')

        raise ValueError(
            f'Storage volume <{prop_key}:{prop_value}> not found'
            ' or not attached to partition')
    # _find_storage_volume()

    def cache(self, key, value=None):
        """Retrieve or store a session object"""
        if value is None:
            return self._cache.get(key, None)
        self._cache[key] = value
        return value
    # cache()

    def compatible(self, other_hypervisor) -> bool:
        """Test if hypervisor definitions are similar"""
        return (isinstance(other_hypervisor, CpcHypervisor)
                and other_hypervisor == self._hypervisor)
    # compatible()

    def connect(self):
        """Connect to HMC"""
        logger.info("Connecting to HMC %s", self._hypervisor.hostname)
        rt_config = zhmcclient.RetryTimeoutConfig(
            connect_timeout=self._connection_options['connect_timeout'],
            operation_timeout=self._connection_options['operation_timeout'],
            status_timeout=self._connection_options['status_timeout'],
        )
        session = zhmcclient.Session(
            self._hypervisor.hostname,
            self._hypervisor.credentials['username'],
            self._hypervisor.credentials['password'],
            retry_timeout_config=rt_config,
            port=self._connection_options['port'],
            verify_cert=self._connection_options['verify_certificate'])

        try:
            session.logon()
        except zhmcclient.ServerAuthError as exc:
            raise RuntimeError(
                f'HMC login failed: {exc.details.message}') from exc

        if audit_id := self._hypervisor.credentials.get('audit-id'):
            session.headers['X-Audit-Id'] = audit_id
        self._client = zhmcclient.Client(session)
        self._cache.clear()
    # connect()

    @staticmethod
    def _normalize_address(address):
        """
        Convert the load address to the format expected by the HMC API.

        Args:
            address (str): string in the format 0.0.1500 or 1500

        Returns:
            str: normalized load address
        """
        return address.replace('.', '')[-5:]
    # _normalize_address()

    def _refresh_partition_properties(self, partition, properties=('status',)):
        """Refresh partition properties from HMC"""
        if properties is None:
            partition.pull_full_properties()
        else:
            partition_props = self._client.session.get(
                f'{partition.uri}?properties={",".join(properties)}')
            partition.update_properties_local(partition_props)
    # _refresh_partition_properties

    def deactivate(self, guest: CpcPartition):
        """Stop a guest"""
        partition = self._find_guest(guest)
        logger.info("Deactivating partition %s", guest.partition_name)

        if partition.manager.cpc.dpm_enabled:
            logger.info("DPM deactivation is not required")
            return

        partition.deactivate()
    # stop()

    def disconnect(self):
        """Disconnect from HMC"""
        if self._client:
            logger.info("Disconnecting from HMC %s", self._hypervisor.hostname)
            self._cache.clear()
            self._client.session.logoff()
            self._client = None
    # disconnect()

    def set_dpm_boot_params(self, guest: CpcPartition, boot_params: dict):
        """Set boot parameters in DPM mode"""
        if boot_params['boot_method'] == 'ftp':
            parsed_url = urlsplit(boot_params['uri'])
            update_props = {
                'boot-device': 'ftp',
                'boot-ftp-host': parsed_url.hostname,
                'boot-ftp-username': parsed_url.username or 'anonymous',
                'boot-ftp-password': parsed_url.password or 'anonymous',
                'boot-ftp-insfile': parsed_url.path,
            }
            self.update_properties(guest, update_props)
        elif boot_params['boot_method'] == 'volume':
            # this boot method requires DPM storage management feature
            cpc = self._client.cpcs.find_by_name(guest.cpc)
            try:
                is_dpm_storage = cpc.feature_enabled('dpm-storage-management')
            except ValueError as exc:
                logger.debug("CPC dpm-storage-management feature query: %s",
                             exc)
                is_dpm_storage = False

            if not is_dpm_storage:
                raise RuntimeError("DPM storage management is not enabled")

            svol_uri = self._find_storage_volume(guest, boot_params)
            update_props = {
                'boot-device': 'storage-volume',
                'boot-storage-volume': svol_uri,
            }
            if boot_params.get('secure_boot', False):
                update_props['secure-boot'] = True

            self.update_properties(guest, update_props)
        elif boot_params['boot_method'] == 'custom':
            # pass through the props
            update_props = {key: value for key, value in boot_params.items()
                            if key.startswith('boot-') or key == 'secure-boot'}
            self.update_properties(guest, update_props)

        else:
            logger.warning("Unknown boot_method %s",
                           boot_params['boot_method'])
    # set_dpm_boot_params()

    def start(self, guest: CpcPartition, boot_params):
        """
        Start a guest

        Performs a start/load/scsi-load action

        Args:
            guest (CpcPartition): guest definition
            boot_params (dict): optional, boot parameters
        """
        partition = self._find_guest(guest)
        if partition.manager.cpc.dpm_enabled:
            # set dpm parameters and activate
            if boot_params:
                self.set_dpm_boot_params(guest, boot_params)
            partition.start()
        else:
            # load classic LPAR
            if partition.prop('status') == 'not-activated':
                partition.activate()

            if not boot_params:
                # load using the address used in the last load.
                partition.load()
                return

            allow_exceptions = boot_params.get(
                'allow_status_exceptions', False)

            if (boot_params['boot_method'] == 'volume'
                    and boot_params['volume_type'] == 'fcp'):
                partition.scsi_load(
                    load_address=self._normalize_address(
                        boot_params['fcp_adapter']),
                    wwpn=boot_params['wwpn'],
                    lun=boot_params['lun'],
                    wait_for_completion=True,
                    allow_status_exceptions=allow_exceptions,
                    force=True,
                    secure_boot=boot_params.get('secure_boot', False)
                )
            elif (boot_params['boot_method'] == 'volume'
                    and boot_params['volume_type'] == 'dasd'):
                store_status = boot_params.get('store_status_indicator', False)
                partition.load(
                    load_address=self._normalize_address(
                        boot_params['volume_id']),
                    wait_for_completion=True,
                    allow_status_exceptions=allow_exceptions,
                    store_status_indicator=store_status,
                    force=True)
            else:
                # non-dpm: only 'volume' method is supported
                logger.warning("Unsupported boot_method %s for partition %s",
                               boot_params['boot_method'], guest.partition_name)
    # start()

    def stop(self, guest: CpcPartition):
        """Stop a guest"""
        partition = self._find_guest(guest)
        logger.info("Stopping partition %s", guest.partition_name)
        partition.stop()
    # stop()

    def update_properties(self, guest: CpcPartition, props: dict):
        """Update parition properties"""
        partition = self._find_guest(guest)
        updated_keys = props.keys()
        logger.debug("Updating partition %s properties %s",
                     partition.name, list(updated_keys))
        # unless we only update boot parameters, partitions have to be
        # stopped/deactivated
        needs_restart = not all(key.startswith('boot-') or key == 'secure-boot'
                                for key in updated_keys)

        partition.update_properties(props)
        if needs_restart:
            partition.stop()
            if not partition.manager.cpc.dpm_enabled:
                partition.deactivate()

    # update_properties()
# HmcHypervisorSession
