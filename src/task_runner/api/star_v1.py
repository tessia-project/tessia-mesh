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
Task Runner API v1

Starlette implementation
"""

#
# IMPORTS
#

import asyncio
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.routing import Route

from ..service_layer import NotFound, ServiceLayer

#
# CONSTANTS AND DEFINITIONS
#


#
# CODE
#

def root(_request):
    """
    API root

    Verify that request is authorized and succeeds
    """
    return JSONResponse({
        'success': True
    })
# root()


def schema(_request):
    """API schema"""
    return JSONResponse({
        '/': 'api root'
    })
# schema()


async def create_task(request):
    """Create a new task"""
    service_layer: ServiceLayer = request.app.state.service_layer
    task = await request.json()
    task_entry = service_layer.add_task(task)
    return JSONResponse({
        'taskId': task_entry.task_id,
        'state': task_entry.state
    }, status_code=201)
# create_task()


def list_tasks(request):
    """List known tasks"""
    service_layer: ServiceLayer = request.app.state.service_layer
    tasks_list = service_layer.list_tasks()
    return JSONResponse([{
        'taskId': task_entry.task_id,
        'state': task_entry.state
    } for task_entry in tasks_list])
# list_tasks()


def get_task(request):
    """Retrieve task status"""
    service_layer: ServiceLayer = request.app.state.service_layer
    task_id = request.path_params['task_id']
    task_entry = service_layer.get_task_status(task_id)

    return JSONResponse({
        'taskId': task_entry.task_id,
        'state': task_entry.state
    })
# get_task()


async def stop_task(request):
    """
    Stop task

    Service layer will wait a little for task to stop,
    but return regardless
    """
    service_layer: ServiceLayer = request.app.state.service_layer
    task_id = request.path_params['task_id']
    task_entry = service_layer.stop_task(task_id)
    for _retries in range(5):
        await asyncio.sleep(0.1)
        task_entry = service_layer.get_task_status(task_entry.task_id)
        if task_entry.state in ('exited', 'lost'):
            # success
            break

    # return what we have
    return JSONResponse({
        'taskId': task_entry.task_id,
        'state': task_entry.state
    })
# stop_task()


async def remove_task(request):
    """
    Remove task from internal lists

    The task will no longer be monitored
    """
    service_layer: ServiceLayer = request.app.state.service_layer
    task_id = request.path_params['task_id']
    success = service_layer.forget_task(task_id)

    return JSONResponse({
        'success': success
    })
# remove_task()

#
#  Exception handlers
#


async def http_exception(_request, exc):
    """Handle common exceptions as JSON dictionary"""
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
# http_exception()


async def service_layer_not_found(_request, exc: NotFound):
    """Handle NotFound exception from service layer"""
    return JSONResponse({"detail": str(exc)}, status_code=404)
# service_layer_not_found()


def service_layer_invalid_value(_request, exc: ValueError):
    """Handle ValueError exception from service layer"""
    return JSONResponse({"detail": str(exc)}, status_code=400)
# err_invalid_value()


def service_layer_runtime_error(_request, exc: RuntimeError):
    """Handle RuntimeError exception from service layer"""
    return JSONResponse({"detail": str(exc)}, status_code=500)
# service_layer_runtime_error()

#
#  Exports
#


# Expose V1 as an application to be able to set custom exception handlers
api = Starlette(routes=[
    Route('/', root),
    Route('/schema', schema),
    Route('/tasks', create_task, methods=['POST']),
    Route('/tasks', list_tasks, methods=['GET']),
    Route('/tasks/{task_id}', get_task, methods=['GET']),
    Route('/tasks/{task_id}', remove_task, methods=['DELETE']),
    Route('/tasks/{task_id}/stop', stop_task, methods=['POST']),
], exception_handlers={
    HTTPException: http_exception,
    NotFound: service_layer_not_found,
    ValueError: service_layer_invalid_value,
    RuntimeError: service_layer_runtime_error
}, debug=True)

api_v1 = {
    'blueprint': api,
    'root': '/v1',
    'min_version': '0.0.0',
    'version': '0.0.1'
}
