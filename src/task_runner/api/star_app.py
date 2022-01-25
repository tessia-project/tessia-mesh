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
REST interface for Task Runner mesh component

Powered by Starlette (ASGI web framework)
"""

#
# IMPORTS
#
import asyncio
import json
import logging
import logging.config
import os

from collections import deque
from functools import partial
from threading import Thread, Event

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from .star_v1 import api_v1
from ..service_layer import ServiceLayer, ServiceLayerWorker

#
# CONSTANTS AND DEFINITIONS
#


DEFAULT_CONFIGURATION = {
    'logging': {
        'version': 1,
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'INFO',
            },
            'file': {
                'class': 'logging.FileHandler',
                'filename': 'task_runner.log',
                'mode': 'w',
                'level': 'DEBUG',
            }
        },
        'loggers': {
            'mesh-scheduler': {
                'level': 'DEBUG',
                'handlers': ['console', 'file']
            },
            'asyncio': {
                'level': 'DEBUG',
                'handlers': ['console', 'file']
            },
        },
    }
}

# Number of timing counts to hold
TIMINGS_BUFFER_LENGTH = 100

# seconds between average timing reports
TIMINGS_REPORT_INTERVAL = 60

# Sync event to shutdown worker
ShutdownEvent = Event()

#
# CODE
#


async def worker_loop(worker: ServiceLayerWorker):
    """Perform worker tasks"""
    timings = deque([0], TIMINGS_BUFFER_LENGTH)
    last_report_time = asyncio.get_running_loop().time()
    logger = logging.getLogger('mesh-scheduler')

    try:
        while not ShutdownEvent.is_set():
            await asyncio.sleep(0.1)
            time_start = asyncio.get_running_loop().time()
            await worker.update_known_tasks()
            time_end = asyncio.get_running_loop().time()

            timings.append(time_end - time_start)
            if time_end > last_report_time + TIMINGS_REPORT_INTERVAL:
                logger.info("Average worker cycle: %.2fs",
                            sum(timings) / len(timings))
                last_report_time = time_end
    finally:
        asyncio.get_running_loop().stop()

# worker_loop()


def _worker_thread_loop(loop):
    """Entry point for worker event loop"""
    loop.run_forever()
# _worker_thread_loop()


def start_worker(service: ServiceLayer):
    """Create a separate loop for the worker"""
    worker = ServiceLayerWorker(service)
    loop = asyncio.new_event_loop()
    loop.create_task(worker_loop(worker), name='worker-loop')
    thread = Thread(target=_worker_thread_loop, args=(loop,), daemon=True)
    thread.start()
# start_worker()


def stop_worker():
    """Stop worker loop"""
    ShutdownEvent.set()
# stop_worker()


#
#  Web server
#


async def http_exception(_request, exc):
    """Handle common exceptions as JSON dictionary"""
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
# http_exception()


async def version(_request):
    """Version"""
    return JSONResponse({
        'name': 'task_runner',
        'apis': [{
            key: api[key]
            for key in ['root', 'version', 'min_version']
        } for api in [api_v1]]
    })
# version()


def create_app() -> Starlette:
    """
    Create Starlette application
    """

    config = DEFAULT_CONFIGURATION.copy()

    # path to configuration
    conf_path = os.getenv('TASK_RUNNER_CONF')
    if conf_path:
        config.update(json.load(conf_path))

    # setting up the logging configuration
    logging.config.dictConfig(config['logging'])

    # create common service layer for whole application
    service_layer = ServiceLayer()
    api_v1['blueprint'].state.service_layer = service_layer

    # Unless Service Layer supports being multiple instances,
    # there must only be one "app" process at all times
    app = Starlette(routes=[
        Route('/', endpoint=version),
        Mount(api_v1['root'], app=api_v1['blueprint'])
    ], exception_handlers={
        HTTPException: http_exception,
    },
        debug=True,
        on_startup=[partial(start_worker, service_layer)],
        on_shutdown=[stop_worker]
    )

    return app
# create_app()
