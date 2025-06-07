WandB Manager
============

Overview
--------
The WandBManager module provides integration with Weights & Biases (W&B) for experiment tracking, logging, and visualization.
This module enables efficient recording and analysis of experimental results and metrics within the garak framework.

Key Features
-----------
- Experiment initialization and configuration
- Logging of attempt results
- Recording of evaluation metrics
- Generation of radar charts
- Efficient batch processing of logs

Configuration
------------
The WandBManager can be configured using YAML configuration files. Here are some example configurations:

Basic Configuration
^^^^^^^^^^^^^^^^^
Basic configuration for W&B integration::

    system:
      wandb_enabled: true
      wandb_project: "my-garak-project"

Classes
-------

WandBManager
^^^^^^^^^^^

.. py:class:: WandBManager

   A class that manages integration with W&B

   .. py:method:: init_wandb(generator_name: str, probe_names: List[str], detector_names: List[str]) -> None

      Initializes a W&B experiment.

      :param generator_name: Name of the generator model
      :param probe_names: List of probe names
      :param detector_names: List of detector names
      :return: None

   .. py:method:: log_attempt(attempt: Attempt) -> None

      Logs an attempt result.

      :param attempt: The attempt object to log
      :return: None

   .. py:method:: flush_attempts() -> None

      Sends pending attempt results to W&B in batch.

      :return: None

   .. py:method:: log_evaluation(evaluator: str, probe: str, detector: str, passed: int, total: int) -> None

      Logs evaluation results.

      :param evaluator: Name of the evaluator
      :param probe: Name of the probe
      :param detector: Name of the detector
      :param passed: Number of passed attempts
      :param total: Total number of attempts
      :return: None

   .. py:method:: flush_evaluations() -> None

      Sends pending evaluation results to W&B in batch.

      :return: None

   .. py:method:: finish_wandb() -> None

      Ends the W&B session.

      :return: None


Implementation Details
--------------------

The WandBManager class implements several key features:

1. **Batch Processing**
   - Attempts and evaluations are stored in memory before being sent to W&B
   - Reduces API calls and improves performance
   - Controlled through flush methods

2. **Data Organization**
   - Structures data in a format suitable for W&B visualization
   - Creates tables for attempt results
   - Generates summary metrics for evaluations

3. **Visualization Support**
   - Supports radar chart generation for evaluation metrics
   - Enables custom visualization through W&B's interface

Notes
-----
- W&B configuration (project name, API key) must be set up properly before use
- `log_attempt` and `log_evaluation` methods store data in memory
- Actual transmission to W&B occurs during `flush_attempts` and `flush_evaluations`
- Regular flushing is recommended to manage memory usage
- The manager handles connection errors and retries automatically

Dependencies
-----------
- wandb
- numpy
- pandas

See Also
--------
- `Weights & Biases Documentation <https://docs.wandb.ai/>`_
- :doc:`../attempt`
- :doc:`../evaluator`

Contributing
-----------
When contributing to this module, please ensure:

1. All new features are properly documented
2. Tests are added for new functionality
3. Existing tests pass
4. Code follows the project's style guidelines 