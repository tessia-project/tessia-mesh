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
Permission Manager API v1
"""

#
# IMPORTS
#

from typing import TypedDict

from flask import Blueprint
from permission_manager.service_layer.entrypoints_handlers \
    import action_permissible_handler

#
# CODE
#

api_version = TypedDict(
    'api_version', {
        'blueprint': Blueprint,
        'root': str,
        'min_version': str,
        'version': str
    }
)

api = Blueprint('v1', __name__, url_prefix='/v1')

api_v1: api_version = {
    'blueprint': api,
    'root': '/v1',
    'min_version': '0.0.0',
    'version': '0.0.1'
}


@api.route('/')
def root():
    """
    API root

    Verify that request is authorized and succeeds
    """
    return {
        'success': True
    }


@api.route('/schema')
def schema():
    """API schema"""
    return {
        '/': 'api root'
    }


@api.route('/is-action-permissible')
def is_action_permissible():
    """
    API: action permission validity

    Checking the permission for the action
    """
    return action_permissible_handler()
