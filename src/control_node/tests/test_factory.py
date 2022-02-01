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
Tessia InstanceFactory unit tests
"""

#
# IMPORTS
#
import json
import os
from binascii import b2a_base64

from ..control_node.certificate_authority import CertificateAuthority, \
    export_key_cert_bundle
from ..control_node.detached import DetachedInstance
from ..control_node.factory import InstanceFactory

#
# CONSTANTS AND DEFINITIONS
#


#
# CODE
#

def get_real_conf_path():
    """Get path to example configuration file"""
    path_to_current_file = os.path.realpath(__file__)
    current_directory = os.path.dirname(path_to_current_file)
    top_directory = current_directory.rsplit('tests', maxsplit=1)[0]
    return os.path.join(top_directory, "conf/default.json")
# get_real_conf_path()


def test_default_configuration_is_correct():
    """Default configuration file should work"""
    with open(get_real_conf_path(), 'rt', encoding='utf-8') as conf_file:
        conf = json.load(conf_file)
    instance = InstanceFactory.create_instance(conf)

    assert isinstance(instance, DetachedInstance)
# test_default_configuration_is_correct()


def test_run_with_predefined_ca():
    """Run with an existing certificate authority"""
    new_ca = CertificateAuthority.create_self_signed()
    ca_cert = new_ca.dump_ca_certificate()
    ca_key = new_ca.dump_ca_private_key('')

    raw_conf = {
        'mode': 'detached',
        'components': {},
        'certificate-authority': {
            'certificate': {
                'type': 'raw',
                'value': ca_cert.decode('utf-8')
            },
            'private-key': {
                'type': 'raw',
                'value': ca_key.decode('utf-8')
            }
        }
    }
    raw_instance = InstanceFactory.create_instance(raw_conf)

    bundle_export_key = 'prettyrandom'
    # pylint:disable=protected-access
    ca_bundle = export_key_cert_bundle(new_ca._ca_key, new_ca._ca, new_ca._ca,
                                       bundle_export_key)
    bundle_conf = {
        'mode': 'detached',
        'components': {},
        'certificate-authority': {
            'pkcs12-bundle': {
                'type': 'base64',
                'value': b2a_base64(ca_bundle).decode('utf-8')
            },
            'import-key': {
                'type': 'raw',
                'value': bundle_export_key
            }
        }
    }
    bundle_instance = InstanceFactory.create_instance(bundle_conf)

    assert isinstance(raw_instance, DetachedInstance)
    assert raw_instance.ca_root.dump_ca_certificate() == ca_cert
    assert isinstance(bundle_instance, DetachedInstance)
    assert bundle_instance.ca_root.dump_ca_certificate() == ca_cert
# test_default_configuration_is_correct()
