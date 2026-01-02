Accelerating garak runs
=======================

Sometimes, we want to run garak faster.
A default run can subsist of 80,000 or more inference requests.
This may take a long time to execute.
Thankfully there are a number of options and techniques built into garak and 
surrounding tooling that are intended to make this workload more accessible.
This documentation page details how garak runs and what can be done in order to
speed runs up.



Target types
------------

Generators in garak can broadly be thought of as one of two types: local models, and remote endpoints.
Local models are generators that load the target on the local machine,  like ``huggingface.Pipeline``; remote endpoints are those that access a target hosted remotely, like ``openai.OpenAICompatible`` or ``nim.NVOpenAIChat``.

Local generators consume resources on the same machine as which garak runs.
This means they only run on machine, and more often than not, it also means that there aren't resources to run more than one instance of a model.
That has the effect of making runs only possible in serial.
Local generators also have to some some orchestration of getting models up and running and keeping them running. 
Since there are so many different kinds of model around, and each of these is often pushing the limits of what's technically and scientifically possible at the time of its release, local generators tend to be a bit prone to mid-run failures, e.g. when a previously-unseen edge case is encountered.

Remote endpoints mean that all this orchestration is sent away to some dedicated service.
This has a few advantages.
First, garak doesn't have to do orchestration.
Second, it can be possible for multiple instances of the target to run in parallel without garak or you having to worry about it.
Third, the people running the endpoint have often done some quality checking and testing to make sure that the endpoint runs well, reducing the chance of the target crashing weirdly.
Fourth, because orchestration -- loading and serving models -- happens remotely, if there is a failure, the solution can be as simple (from garak's point of view) as re-sending the inference request to the target endpoint. Garak is generally pretty gentle but tenacious when it comes to dealing with endpoint failure - we know that runs can take a while and we want to mitigate the need to "babysit" them, by having garak politely try to recover the target.

As you might be able to guess by now, there are some good advantages to using remote endpoint generators, and some notable disadvantages to local model generators. Garak maintainers strongly recommend using remote generators if you're trying to do things quickly. Not least because it enables parallelization.


Parallelization within garak
----------------------------
Garak offers a couple of options for parallelization, directly available on the CLI or via config.


Parallel attempts
^^^^^^^^^^^^^^^^^

Running inference in serial is slow and often takes days, sometimes weeks. 
During probing, garak can marshall all the prompts it knows it's going to pose, and parallise these at attempt level.
This means taht multiple generations form the same prompt still occur in serial. 

It's recommended to use set ``system.parallel_attempts: 32`` if you're using a remotely hosted endpoint.
This will run up to 32 inference requests at a time, and cover a broad range of probes. Run completion time depends on how fast the target is and how much compute is allocated.
If you need more, you can sometimes ask the hosting service to raise capacity and then also raise ``system.parallel_attempts`` if you're in a rush. 

Note that garak handles timed-out requests itself, so it recovers from events like endpoints timing out and dropping requests when ``system.parallel_attempts`` is too high. 
On the other hand, dropped requests don't look great on the dashboards of the people managing whichever endpoint your targeting, and will maybe cause tickets to be raised, so it's better to get in touch before raising this value super high.




Limits in parallization
^^^^^^^^^^^^^^^^^^^^^^^

FDs and parallelization
"""""""""""""""""""""""

Parallelization within garak operates by creating a new thread/process for each parallel part.
Doing this with higher numbers can lead to a crash, if your system hits a limit.
For example, the number of open files can be limited in a Linux shell session.
The garak config item ``system.max_workers`` sets an upper bound for the``parallel_attempts`` value.
The idea here is to try to provide early failure, rather than hitting a system limit mid-run and breaking then.
You can just raise ``system.max_workers`` to whatever you want - but be aware that you may hit a system limit during the run.
Often these can be raised with tools like ulimit (on Linux).
Garak ``system.max_workers`` only provides a protective internal limit, and adjusting it does not make any changes to the operating system environment.


Probe-level serial processing
"""""""""""""""""""""""""""""

Garak parallelization runs during each probe.
This means that while inference requests made by an individual probe can be run in parallel, the probes themself run in serial.
That is, all requests made by one probe must be complete before any work can be requested by the next probe.
If you want to get around this, there is a route available probe splitting and aggregation, described below.

Generations
-----------

Another thing to try to make things go quicker is to reduce generations: 5 to a lower number; this directly affects the amount of inference demanded. Taking this down to 1 can mean we miss some transient LLM behaviours and so the recommended minimum is 2.

Prompt cap
----------

The config item ``run.soft_probe_prompt_cap`` specifies a soft cap for the maximum number of prompts that a probe should generate.
It's a soft cap because not all probes will comply.
If you want your run to go faster, many probes will generate less workload when this number is reduced - at the cost of reduced accuracy in results.
Default in garak v0.13.1 is ``run.soft_probe_prompt_cap: 256``.

Aggregation
-----------

There's a tool for merging garak reports.
This means that multiple garak runs can execute independently and then the output can be compiled into one report.
Being able to do this affords parallelization, for example on SLURM/OCI clusters where an entire executable job has to be specified.
The tool is ``aggregate_reports`` and runs from the command line.
You can get help by running ``python -m garak.analyze.aggregate_reports``.

Probe aggregation
^^^^^^^^^^^^^^^^^

One way of achieving parallel probing is by splitting garak probing up into many jobs each with one probe given in ``plugins.probe_spec``.
Each job should write to a distinct report file.
When complete, the resulting report JSONL files can be aggregated into one using the ``aggregate_reports`` tool.


.. Aggregation with lower generations
.. ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. When it's not enough to split runs up by probe - perhaps there's a slow probe, or slow model - one can also use aggregation and multiple runs to simulate the effect of the generations parameter.
.. To do this, set config param ``run.generations: 1``, and then create multiple copies of the same garak job, writing to distinct report files.
.. Then, use ``aggregate_reports`` to put all the reports back together.
.. This works by reducing the granularity of the individual job, and can be great if you have a very broad cluster.