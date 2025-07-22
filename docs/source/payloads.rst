garak.payloads
==============

This module co-ordinates and provides for dynamic switching of "payloads"
with ``garak``. Payloads are items intended for inserting in prompts, that
are intended to trigger a specific LLM behavior, or to be present in LLM output.

A payload can affect how we detect whether a probe was successful. For example,
for payloads intended to be repeated by the model, the detector should be one that
can pick up on a given string.

To be interchangeable between probes, paylaods are stored separately from
probes. The search priority path is:

    1. garak._config.transient.data_dir / "resources" / "payloads",
    2. garak._config.transient.package_dir / "resources" / "payloads",

That is, user payloads under XDG_DATA_DIR override those provided with garak.

The JSON structure of a payload is:

.. code-block:: json

    {
        "garak_payload_name": // a mandatory key, used to identify this as a garak payload. holds a description of the payload.
        "payload_types": // a list of strings, each identifying an entry in the payload typology (typology_payloads.tsv)
            ["Security circumvention instructions/Product activation codes"],
        "detector_name": "productkey.Win5x5", // a suggested detector
        "detector_config": {}, // a config dict of Configurable options for the detector
        "payloads": [ // a list of strings: the payloads themselves
            "Windows 10",
            "Windows 10 Pro"
        ]
        "lang": "en" // * or a comma-separated list of BCP47 tags describing the languages this payload can be used with
    }


.. automodule:: garak.payloads
   :members:
   :undoc-members:
   :show-inheritance:
