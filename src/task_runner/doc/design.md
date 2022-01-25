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

# Task Runner node design

Task Runner starts incoming tasks, defined by available state machines. Tasks are independent of each other and are started as soon as possible after a request was received.

As a tessia-mesh node, Task Runner provides a REST API to start, stop and query running tasks. 

Tasks (implemented by state machines) may have very differing behaviour, which would require running them as separate processes and in separate environments.

For different use cases there may be several Task Runner instances with different runner implementations. Choice of implementation depends on the requirements and availability of operating system components.

## Operation requirements

1. The node should be able to start and stop tasks.

   Requirement to stop tasks excludes the usage of individual threads (at least in python environment) - tasks have to be at least different processes.

2. Running logs for a task should be available

   Node should be able to stream rich output (i.e. with additional information per log entry) from the task runner. There is no strict timing to be met, but generally new log entries should be sent over stream within a few seconds after they were emitted by running task.

   There are not many options to implement streaming; for HTTP it is chunked encoding, server-sent events or websockets. Of these chunked encoding is preferred: SSE stream has character set limitations and cannot use compression efficiently, websockets require additional protocol to be established.

3. Tasks should be isolated from each other

   Some isolation is achieved by having tasks as different processes, but tasks may have additional output, temporary files and even subprocesses. A separate working directory or even container isolation is recommended.

   Another option is to not run multiple tasks at all, which is
   suitable for one-shot or serial tasks.

An additional requirement for long-running tessia deployments:

4. Tasks started by Task Runner should not be interrupted by mesh restarts (redeployments). 

   This implies keeping the last known state and being able to recover from it.

## Implementation choices

Due to presence of streaming and periodic workloads, an async implementation looks more favourable; so the choice narrows down to picking a web server, either stand-alone (aiohttp) or with ASGI protocol support (WSGI does not fully support chunked streaming, because it blocks a worker thread).

One of the concerns is whether to have a single-process server, which handles both requests and task monitoring, or to separate web part from monitoring part into distinct processes.

Benefits of having monitoring separate from web service:
- no or simpler recovery strategy for redeployment: monitoring does not have to be restarted or there can be graceful shutdown and rollover
- nodes can be easily scaled as worker processes in a web server environment, as there is no state shared or global monitoring threads

Benefits of having single process for web and monitoring:
- no additional communication protocol between two servers
- simpler deployment, as all nodes are manageable by control node

