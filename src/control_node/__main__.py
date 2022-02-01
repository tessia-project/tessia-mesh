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

"""
Tessia instance configurator
"""

#
# IMPORTS
#
import argparse
import json
import logging
import os.path
import signal
import time

from .control_node.certificate_authority import CertificateAuthority, \
    export_key_cert_bundle
from .control_node.detached import DetachedInstance
from .control_node.errors import StartInstanceError
from .control_node.factory import InstanceFactory

#
# CONSTANTS AND DEFINITIONS
#
DESCRIPTION = """Tessia instance configurator

Use this program to deploy an instance of Tessia.
"""

# Status update interval, seconds
MONITOR_INTERVAL = 5.0

#
# CODE
#


def certificate_export(key, crt, ca_auth: CertificateAuthority, name_tag: str,
                       export_options: dict):
    """
    Export extra requested certificates
    """
    if export_options['format'] == 'files':
        ca_auth.export_key_cert_to_directory(
            export_options['dir'], key, crt, name_tag)
    elif export_options['format'] == 'pkcs12':
        bundle = export_key_cert_bundle(key, crt, ca_auth.root,
                                        export_options['export_key'])
        with open(os.path.join(export_options['dir'], f'{name_tag}.pfx'),
                  'wb') as bundle_file:
            bundle_file.write(bundle)
# certificate_export()


def supervise(instance: DetachedInstance):
    """Monitor tessia instance and close when needed"""
    # Preventively set default signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal.default_int_handler)
    logging.info("Monitoring Tessia instance")
    try:
        # wait until termination
        while all(instance.verify().values()):
            time.sleep(MONITOR_INTERVAL)
        logging.info("Shutting down tessia instance")

    except KeyboardInterrupt:
        logging.info("Ctrl+C received, exiting")
        instance.stop()
    finally:
        instance.cleanup()
# supervise()


def main():
    """
    Command-line entrypoint
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)-15s %(message)s')
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='./conf/default.json',
                        help="Path to configuration file")
    parser.add_argument('--only-check', action='store_true',
                        help="Do not start instance, but check configuration "
                        "and perform CA actions")
    parser.add_argument('--make-client-cert', action='store_true',
                        help="Generate additional client certificate "
                             "to communicate with components")
    parser.add_argument('--client-cert-name', default='client',
                        help="Name identifier for client certificate")
    parser.add_argument('--make-server-cert', action='store_true',
                        help="Generate additional server certificate "
                             "for a mesh component")
    parser.add_argument('--server-cert-name', default='server',
                        help="Name identifier for server certificate")
    parser.add_argument('--server-cert-hostname', default='localhost',
                        help="Hostname for server certificate")
    parser.add_argument('--export-format', choices=['files', 'pkcs12'],
                        default='files',
                        help="Export generated certificates as "
                        "separate PEM files or a PKCS12 container")
    parser.add_argument('--export-dir', default='./',
                        help="Export directory")
    parser.add_argument('--pkcs12-export-phrase', default='pkcs12',
                        help="Export phrase for PKCS12 container")

    args = parser.parse_args()
    logging.info('Loading configuration from %s', args.config)

    with open(args.config, 'r', encoding='utf-8') as conf_file:
        configuration = json.load(conf_file)

    factory = InstanceFactory()
    logging.info('Creating Tessia instance')
    instance = factory.create_instance(configuration)

    export_options = {
        'dir': args.export_dir,
        'format': args.export_format,
        'export_key': args.pkcs12_export_phrase
    }
    if args.make_client_cert:
        # write additional client certificates
        logging.info('Writing additional client certificate')
        key, crt = instance.ca_root.create_component_client_certificate(
            args.client_cert_name)
        certificate_export(key, crt, instance.ca_root, 'client',
                           export_options)

    if args.make_server_cert:
        # write additional server certificates
        logging.info('Writing additional server certificate')
        key, crt = instance.ca_root.create_component_server_certificate(
            args.server_cert_name, args.server_cert_hostname)
        certificate_export(key, crt, instance.ca_root, 'server',
                           export_options)

    if args.only_check:
        return

    logging.info('Writing Tessia instance configuration')
    instance.setup()

    logging.info('Starting Tessia instance')
    try:
        instance.run()
    except StartInstanceError:
        instance.cleanup()
        raise

    if isinstance(instance, DetachedInstance):
        supervise(instance)
# main()


if __name__ == "__main__":
    main()
