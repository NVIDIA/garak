# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import inspect
import os
from garak import _config
from garak import _plugins
from garak.exception import APIKeyMissingError


class Configurable:
    _supported_params = None  # override to provide a list of supported values

    def _load_config(self, config_root=_config):
        if hasattr(self, "_instance_configured"):
            return  # only load once, this will ensure the config is not rerun for extending classes
        local_root = (
            config_root.plugins if hasattr(config_root, "plugins") else config_root
        )
        namespace_parts = self.__module__.split(".")
        # last part is the namespace, second to last is the plugin type
        # this will support something like:
        # plugins['detectors'][x]['generators']['rest']['RestGenerator']
        # plugins['detectors'][x]['generators']['rest']
        # plugins['probes'][y]['generators']['rest']['RestGenerator']
        if len(namespace_parts) > 2:
            # example class expected garak.generators.huggingface.Pipeline
            # spec_type = generators
            # namespace = huggingface
            # classname = Pipeline
            # current expected spec_type values are `_plugins.PLUGIN_TYPES`
            spec_type = namespace_parts[-2]
            namespace = namespace_parts[-1]
            classname = self.__class__.__name__
            namespaced_klass = f"{namespace}.{classname}"
            plugins_config = {}
            if isinstance(local_root, dict) and spec_type in local_root:
                plugins_config = local_root[spec_type]
            elif hasattr(local_root, spec_type):
                plugins_config = getattr(local_root, spec_type)
            if namespace in plugins_config:
                # example values:
                # generators: `nim`/`openai`/`huggingface`
                # probes: `dan`/`gcg`/`xss`/`tap`/`promptinject`
                attributes = plugins_config[namespace]
                self._apply_config(attributes)
                if classname in attributes:
                    self._apply_config(attributes[classname])
            elif namespaced_klass in plugins_config:
                # maintain support for this as consistent with cli options at this time
                self._apply_config(plugins_config[namespaced_klass])
        self._apply_run_defaults()
        self._apply_missing_instance_defaults()
        if hasattr(self, "ENV_VAR"):
            if not hasattr(self, "key_env_var"):
                self.key_env_var = self.ENV_VAR
        self._validate_env_var()
        self._instance_configured = True

    def _apply_config(self, config):
        classname = self.__class__.__name__
        init_params = inspect.signature(self.__init__).parameters
        for k, v in config.items():
            if k in _plugins.PLUGIN_TYPES or k == classname:
                # skip entries for more qualified items or any plugin type
                # should this be coupled to `_plugins`?
                continue
            if (
                isinstance(self._supported_params, tuple)
                and k not in self._supported_params
            ):
                # if the class has a set of supported params skip unknown params
                # should this pass signature arguments as supported?
                logging.warning(
                    f"Unknown configuration key for {classname}: '{k}' - skipping"
                )
                continue
            if hasattr(self, k):
                # do not override values provide by caller that are not defaults
                if k in init_params and (
                    init_params[k].default is inspect.Parameter.empty
                    or (
                        init_params[k].default is not inspect.Parameter.empty
                        and getattr(self, k) != init_params[k].default
                    )
                ):
                    continue
                if isinstance(v, dict):  # if value is an existing dictionary merge
                    v = getattr(self, k) | v
            setattr(self, k, v)  # This will set attribute to the full dictionary value

    def _apply_run_defaults(self):
        for config_obj, defaults in [
            (_config.system, getattr(self, "_system_params", [])),
            (_config.run, getattr(self, "_run_params", [])),
        ]:
            for v in defaults:
                if not hasattr(self, v) and hasattr(config_obj, v):
                    setattr(self, v, getattr(config_obj, v))

    def _apply_missing_instance_defaults(self):
        # class.DEFAULT_PARAMS['generations'] -> instance.generations
        if hasattr(self, "DEFAULT_PARAMS"):
            for k, v in self.DEFAULT_PARAMS.items():
                if not hasattr(self, k):
                    setattr(self, k, v)
                elif isinstance(v, dict):
                    v = v | getattr(self, k)
                    setattr(self, k, v)

    def _validate_env_var(self):
        if hasattr(self, "key_env_var"):
            if not hasattr(self, "api_key") or self.api_key is None:
                self.api_key = os.getenv(self.key_env_var, default=None)
                if self.api_key is None:
                    if hasattr(
                        self, "generator_family_name"
                    ):  # special case may refactor later
                        family_name = self.generator_family_name
                    else:
                        family_name = self.__module__.split(".")[-1].title()
                    raise APIKeyMissingError(
                        f'🛑 Put the {family_name} API key in the {self.key_env_var} environment variable (this was empty)\n \
                        e.g.: export {self.key_env_var}="XXXXXXX"'
                    )
