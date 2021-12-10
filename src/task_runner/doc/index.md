<!--
Copyright 2021 IBM Corp.

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

# Tessia Task Runner component

A component to start and monitor tasks.

## Setup

Component requires a working directory for the tasks. Create a `/var/lib/tessia-mesh/task_runner` directory and set ownership to the user running the component. Tasks will each have a separate subdirectory in it.

## Run the component

As a tessia-mesh node, the component can act as an API server. [Design limitations](design.md) require that the component runs in an async environment, so it should be run in an ASGI-compatible web server (such as `uvicorn` or `gunicorn` with uvicorn workers).

Start a node:
```sh
python3 -m gunicorn  -k uvicorn.workers.UvicornWorker 'task_runner.api.star_app:create_app'
```

## Running tasks

To submit a task perform a POST request to `/v1/tasks` endpoint:
```sh
curl -s -X POST --url http://localhost:8000/v1/tasks  --data-binary @task_runner/doc/sample_task.json -H 'Content-Type: application/json'
```

Response will be task ID and status:
```json
{"taskId":"3df2bb24","state":"running"}
```

TaskRunner can be started on its own in command-line mode:
```sh
python -m task_runner.lib.runner task_runner/doc/sample_task.json
```

The task will be run with identifier 'cli' and its results put into current directory.

## Operation

Tasks are started as separate processes and monitor by a respective environment instance (e.g. MultiprocessEnvironment). 

Environment is responsible for starting and monitoring processes that execute certain tasks. As tasks are separate and have their own working directries, they can operate independently of the component, so the component can be restarted without losing task progress.

Regardless of the environment, each task process is an instance of `runner.TaskRunner`. It keeps a status file with its own information and timestamps, and task output is collected to the output file.

Status file are a fallback mechanism that can be used by environment to determine if a task is still running, has completed or stalled (indicated by stale timestamps). For example, MultiprocessEnvironment cannot restore TaskRunner objects after restart, but can still monitor task execution using status files.

