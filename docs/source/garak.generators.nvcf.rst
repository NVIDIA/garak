garak.generators.nvcf
=====================

This garak generator is a connector to NVIDIA Cloud Functions. It permits fast
and flexible generation.

NVCF functions work by sending a request to an invocation endpoint, and then polling
a status endpoint until the response is received. The cloud function is described
using a UUID, which is passed to garak as the ``model_name``. API key should be placed in
environment variable ``NVCF_API_KEY`` or set in a garak config. For example:

.. code-block::

   export NVCF_API_KEY="example-api-key-xyz"
   garak -m nvcf -n 341da0d0-aa68-4c4f-89b5-fc39286de6a1


Configuration
-------------

Configurable values:

* temperature - Temperature for generation. Passed as a value to the endpoint.
* top_p - Number of tokens to sample. Passed as a value to the endpoint.
* invoke_uri_base - Base URL for the NVCF endpoint (default is for NVIDIA-hosted functions).
* status_uri_base - URL to check for request status updates (default is for NVIDIA-hosted functions).
* timeout - Read timeout for HTTP requests (note, this is network timeout, distinct from inference timeout)
* version_id - API version id, postpended to endpoint URLs if supplied
* stop_on_404 - Give up on endpoints returning 404 (i.e. nonexistent ones)
* extra_params - Dictionary of optional extra values to pass to the endpoint. Default ``{"stream": False}``.

Some NVCF instances require custom parameters, for example a "model" header. These
can be asserted in the NVCF config. For example, this cURL maps to the following
garak YAML:


.. code-block::

   curl -s -X POST 'https://api.nvcf.nvidia.com/v2/nvcf/pexec/functions/341da0d0-aa68-4c4f-89b5-fc39286de6a1' \
   -H 'Content-Type: application/json' \
   -H 'Authorization: Bearer example-api-key-xyz' \
   -d '{
         "messages": [{"role": "user", "content": "How many letters are in the word strawberry?"}],
         "model": "prefix/obsidianorder/terer-nor",
         "max_tokens": 1024,
         "stream": false
      }'

.. code-block:: yaml

   ---
   plugins:
      generators:
         nvcf:
            NvcfChat:
               api_key: example-api-key-xyz
               max_tokens: 1024
               extra_params:
                  stream: false
                  model: prefix/obsidianorder/terer-nor
      model_type: nvcf.NvcfChat
      model_name: 341da0d0-aa68-4c4f-89b5-fc39286de6a1

The ``nvcf`` generator uses the standard garak generator mechanism for
``max_tokens``, which is why this value is set at generator-level rather than
as a key-value pair in ``extra_params``.


Scaling
-------

The NVCF generator supports parallelisation and it's recommended to use this,
invoking garak with ``--parallel_attempts`` set to a value higher than one.
IF the NVCF times out due to insufficient capacity, garak will note this,
backoff, and retry the request later.

.. code-block::

   garak -m nvcf -n 341da0d0-aa68-4c4f-89b5-fc39286de6a1 --parallel_attempts 32


Or, as yaml config:

.. code-block:: yaml

   ---
   system:
      parallel_attempts: 32
   plugins:
      model_type: nvcf.NvcfChat
      model_name: 341da0d0-aa68-4c4f-89b5-fc39286de6a1




.. automodule:: garak.generators.nvcf
   :members:
   :undoc-members:
   :show-inheritance:
