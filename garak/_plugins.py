# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Functions for working with garak plugins (enumeration, loading, etc)"""

import importlib
import inspect
import json
import logging
import shutil
import os
from datetime import datetime, timezone
from threading import Lock
from typing import List, Callable, Union
from pathlib import Path

from garak import _config
from garak.exception import GarakException, ConfigFailure

PLUGIN_TYPES = ("probes", "detectors", "generators", "harnesses", "buffs")
PLUGIN_CLASSES = ("Probe", "Detector", "Generator", "Harness", "Buff")
TIME_FORMAT = "%Y-%m-%d %H:%M:%S %z"


class PluginEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return sorted(list(obj))  # allow set as list, assumes values can be sorted
        if isinstance(obj, Path):
            # relative path for now, may be better to suppress `Path` objects
            return str(obj).replace(str(_config.transient.package_dir), "")
        try:
            return json.JSONEncoder.default(self, obj)
        except TypeError as e:
            logging.debug("Attempt to serialize JSON skipped: %s", e)
            return None  # skip items that cannot be serialized at this time


class PluginCache:
    _plugin_cache_filename = (
        _config.transient.package_dir / "resources" / "plugin_cache.json"
    )
    _user_plugin_cache_filename = (
        _config.transient.cache_dir / "resources" / "plugin_cache.json"
    )
    _plugin_cache_dict = None

    _mutex = Lock()

    def __init__(self) -> None:
        if PluginCache._plugin_cache_dict is None:
            PluginCache._plugin_cache_dict = self._load_plugin_cache()

    @staticmethod
    def _extract_modules_klasses(base_klass):
        return [  # Extract only classes with same source package name
            name
            for name, klass in inspect.getmembers(base_klass, inspect.isclass)
            if klass.__module__.startswith(base_klass.__name__)
            and not inspect.isabstract(klass)
        ]

    def _load_plugin_cache(self):
        assert os.path.exists(
            self._plugin_cache_filename
        ), f"{self._plugin_cache_filename} is missing or corrupt."

        base_time = datetime.fromtimestamp(
            os.path.getmtime(self._plugin_cache_filename), tz=timezone.utc
        )
        update_user_file = False
        if not os.path.exists(self._user_plugin_cache_filename):
            update_user_file = True
        else:
            user_time = datetime.fromtimestamp(
                os.path.getmtime(self._user_plugin_cache_filename), tz=timezone.utc
            )
            if base_time > user_time:
                update_user_file = True
        if update_user_file:
            self._user_plugin_cache_filename.parent.mkdir(
                mode=0o740, parents=True, exist_ok=True
            )
            shutil.copy2(self._plugin_cache_filename, self._user_plugin_cache_filename)
            user_time = base_time

        with open(
            self._user_plugin_cache_filename, "r", encoding="utf-8"
        ) as cache_file:
            local_cache = json.load(cache_file)

        # validate cache state on startup
        if not self._valid_loaded_cache(local_cache, user_time):
            self._build_plugin_cache()
            with open(
                self._user_plugin_cache_filename, "r", encoding="utf-8"
            ) as cache_file:
                local_cache = json.load(cache_file)

        return local_cache

    def _valid_loaded_cache(self, local_cache, user_time):
        # verify all known plugins
        for plugin_type in PLUGIN_TYPES:
            validated_plugin_filenames = set()
            prev_mod = None
            plugins = local_cache.get(plugin_type, {})
            for k in plugins:
                category, module, klass = k.split(".")
                if module != prev_mod:
                    prev_mod = module
                    # TODO: only one possible location for now, expand when `user` plugins are supported
                    file_path = (
                        _config.transient.package_dir / category / f"{module}.py"
                    )
                    if os.path.exists(file_path):
                        validated_plugin_filenames.add(file_path)
                        mod_time = datetime.fromtimestamp(
                            os.path.getmtime(file_path), tz=timezone.utc
                        )
                    else:
                        # file not found force cache rebuild
                        mod_time = datetime.now(timezone.utc)
                    if mod_time > user_time:
                        # rebuild all for now, this can be more made more selective later
                        return False

            # if all known are up-to-date check filesystem for missing
            found_filenames = set()
            plugin_path = _config.transient.package_dir / plugin_type
            for module_filename in sorted(os.listdir(plugin_path)):
                if not module_filename.endswith(".py"):
                    continue
                if module_filename.startswith("__"):
                    continue
                if module_filename.startswith("_"):
                    continue
                found_filenames.add(plugin_path / module_filename)
            if found_filenames != validated_plugin_filenames:
                return False

        return True  # all checks passed the cache is valid

    def _build_plugin_cache(self):
        """build a plugin cache file to improve access times

        This method writes only to the user's cache (currently the same as the system cache)
        TODO: Enhance location of user cache to enable support for in development plugins.
        """
        logging.debug("rebuilding plugin cache")
        with PluginCache._mutex:
            local_cache = {}

            for plugin_type in PLUGIN_TYPES:
                plugin_dict = {}
                for plugin in self._enumerate_plugin_klasses(plugin_type):
                    plugin_name = ".".join(
                        [plugin.__module__, plugin.__name__]
                    ).replace("garak.", "")
                    plugin_dict[plugin_name] = PluginCache.plugin_info(plugin)

                sorted_keys = sorted(list(plugin_dict.keys()))
                local_cache[plugin_type] = {i: plugin_dict[i] for i in sorted_keys}

            with open(
                self._user_plugin_cache_filename, "w", encoding="utf-8"
            ) as cache_file:
                json.dump(local_cache, cache_file, cls=PluginEncoder, indent=2)

    def _enumerate_plugin_klasses(self, category: str) -> List[Callable]:
        """obtain all"""
        if category not in PLUGIN_TYPES:
            raise ValueError("Not a recognised plugin type:", category)

        base_mod = importlib.import_module(f"garak.{category}.base")

        base_plugin_classnames = set(self._extract_modules_klasses(base_mod))

        module_plugin_names = set()

        for module_filename in sorted(
            os.listdir(_config.transient.package_dir / category)
        ):
            if not module_filename.endswith(".py"):
                continue
            if module_filename.startswith("__"):
                continue
            module_name = module_filename.replace(".py", "")
            mod = importlib.import_module(f"garak.{category}.{module_name}")
            module_entries = set(self._extract_modules_klasses(mod))

            for module_entry in module_entries:
                obj = getattr(mod, module_entry)
                for interface in base_plugin_classnames:
                    klass = getattr(base_mod, interface)
                    if issubclass(obj, klass):
                        module_plugin_names.add(obj)

        return module_plugin_names

    def instance() -> dict:
        return PluginCache()._plugin_cache_dict

    def plugin_info(plugin: Union[Callable, str]) -> dict:
        """retrieves the standard attributes for the plugin type"""
        if isinstance(plugin, str):
            plugin_name = plugin
            category = plugin_name.split(".")[0]

            if category not in PLUGIN_TYPES:
                raise ValueError(f"Not a recognised plugin type: {category}")

            cache = PluginCache.instance()
            with PluginCache._mutex:
                plugin_metadata = cache[category].get(plugin_name, {})

            if len(plugin_metadata) > 0:
                return plugin_metadata
            else:
                # the requested plugin is not cached import the class for eval
                parts = plugin.split(".")
                match len(parts):
                    case 3:
                        try:
                            module = ".".join(parts[:-1])
                            klass = parts[-1]
                            imported_module = importlib.import_module(f"garak.{module}")
                            plugin = getattr(imported_module, klass)
                        except (AttributeError, ModuleNotFoundError) as e:
                            if isinstance(e, AttributeError):
                                msg = f"Not a recognised plugin from {module}: {klass}"
                            else:
                                msg = f"Not a recognised plugin module: {plugin}"
                            raise ValueError(msg)
                    case _:
                        raise ValueError(f"Not a recognised plugin class: {plugin}")
        else:
            plugin_name = ".".join([plugin.__module__, plugin.__name__]).replace(
                "garak.", ""
            )
            category = plugin_name.split(".")[0]

        try:
            base_attributes = []
            base_mod = importlib.import_module(f"garak.{category}.base")
            base_plugin_classes = set(PluginCache._extract_modules_klasses(base_mod))
            if plugin.__module__ in base_mod.__name__:
                # this is a base class enumerate all
                base_attributes = dir(plugin)
            else:
                for klass in base_plugin_classes:
                    # filter to the base class actually implemented
                    if issubclass(plugin, getattr(base_mod, klass)):
                        base_attributes += PluginCache.plugin_info(
                            getattr(base_mod, klass)
                        ).keys()

            plugin_metadata = {}
            priority_fields = ["description"]
            skip_fields = [
                "prompts",
                "triggers",
                "post_buff_hook",
                "recommended_detector",
            ]

            # description as doc string will be overwritten if provided by the class
            desc = plugin.__doc__
            if desc is not None:
                plugin_metadata["description"] = desc.split("\n")[0]

            for v in priority_fields:
                if hasattr(plugin, v):
                    plugin_metadata[v] = getattr(plugin, v)
            for v in sorted(dir(plugin)):
                if v in priority_fields or v in skip_fields:
                    continue
                value = getattr(plugin, v)
                if (
                    v.startswith("_")
                    or inspect.ismethod(value)
                    or inspect.isfunction(value)
                    or v not in base_attributes
                ):
                    continue
                plugin_metadata[v] = value

        except ValueError as e:
            logging.exception(e)
        except Exception as e:
            logging.error(f"Plugin {plugin_name} not found.")
            logging.exception(e)

        # adding last class modification time to cache allows for targeted update in future
        current_mod = importlib.import_module(plugin.__module__)
        mod_time = datetime.fromtimestamp(
            os.path.getmtime(current_mod.__file__), tz=timezone.utc
        )
        plugin_metadata["mod_time"] = mod_time.strftime(TIME_FORMAT)

        return plugin_metadata


class PluginProvider:
    """Central registry of plugin instances

    Newly requested plugins are first checked against this Provider for duplication."""

    _mutex = Lock()

    _instance_cache = {}

    @staticmethod
    def getInstance(klass_def, config_root):
        with PluginProvider._mutex:
            klass_instances = PluginProvider._instance_cache.get(klass_def, {})
            return klass_instances.get(str(config_root), None)

    @staticmethod
    def storeInstance(plugin, config_root):
        klass_instances = PluginProvider._instance_cache.get(plugin.__class__, None)
        if klass_instances is None:
            klass_instances = {}
            PluginProvider._instance_cache[plugin.__class__] = klass_instances
        klass_instances[str(config_root)] = plugin


def plugin_info(plugin: Union[Callable, str]) -> dict:
    return PluginCache.plugin_info(plugin)


def enumerate_plugins(
    category: str = "probes", skip_base_classes=True
) -> List[tuple[str, bool]]:
    """A function for listing all modules & plugins of the specified kind.

    garak's plugins are organised into four packages - probes, detectors, generators
    and harnesses. Each package contains a base module defining the core plugin
    classes. The other modules in the package define classes that inherit from the
    base module's classes.

    enumerate_plugins() works by first looking at the base module in a package
    and finding the root classes here; it will then go through the other modules
    in the package and see which classes can be enumerated from these.

    :param category: the name of the plugin package to be scanned; should
      be one of probes, detectors, generators, or harnesses.
    :type category: str
    """

    if category not in PLUGIN_TYPES:
        raise ValueError("Not a recognised plugin type:", category)

    plugin_class_names = set()

    for k, v in PluginCache.instance()[category].items():
        if skip_base_classes and ".base." in k:
            continue
        enum_entry = (k, v["active"])
        plugin_class_names.add(enum_entry)

    return sorted(plugin_class_names)


def load_plugin(path, break_on_fail=True, config_root=_config) -> object:
    """load_plugin takes a path to a plugin class, and attempts to load that class.
    If successful, it returns an instance of that class.

    :param path: The path to the class to be loaded, e.g. "probes.test.Blank"
    :type path: str
    :param break_on_fail: Should we raise exceptions if there are problems with the load?
      (default is True)
    :type break_on_fail: bool
    """
    try:
        parts = path.split(".")
        match len(parts):
            case 2:
                category, module_name = parts
                try:
                    generator_mod = importlib.import_module(
                        f"garak.{category}.{module_name}"
                    )
                except ModuleNotFoundError as e:
                    raise ValueError(
                        f"Unknown plugin module specification: {category}.{module_name}"
                    ) from e
                if generator_mod.DEFAULT_CLASS:
                    plugin_class_name = generator_mod.DEFAULT_CLASS
                else:
                    raise ValueError(
                        f"module {module_name} has no default class; pass module.ClassName to target_type"
                    )
            case 3:
                category, module_name, plugin_class_name = parts
            case _:
                raise ValueError(
                    f"Attempted to load {path} with unexpected number of tokens."
                )
    except ValueError as ve:
        if break_on_fail:
            raise ValueError(
                f'Expected plugin name in format category.module_name.class_name or category.module_name, got "{path}"'
            ) from ve
        else:
            return False
    module_path = f"garak.{category}.{module_name}"
    try:
        mod = importlib.import_module(module_path)
    except Exception as e:
        logging.warning("Exception failed import of %s", module_path, exc_info=e)
        if break_on_fail:
            raise ValueError(
                "❌ Didn't successfully import "
                + category
                + " plugin: '"
                + module_name
                + "'\n- Check spelling and garak log"
            ) from e
        else:
            return False

    try:
        klass = getattr(mod, plugin_class_name)
        if inspect.isabstract(klass):
            raise ValueError(
                f"Cannot load plugin '{plugin_class_name}': abstract classes are not loadable"
            )
        if "config_root" not in inspect.signature(klass.__init__).parameters:
            raise ConfigFailure(
                'Incompatible function signature: plugin must take a "config_root"'
            )
        plugin_instance = PluginProvider.getInstance(klass, config_root)
        if plugin_instance is None:
            plugin_instance = klass(config_root=config_root)
            PluginProvider.storeInstance(plugin_instance, config_root)
    except Exception as e:
        logging.warning(
            "Exception instantiating %s.%s: %s",
            module_path,
            plugin_class_name,
            str(e),
            exc_info=e,
        )
        if break_on_fail:
            raise GarakException(e) from e
        else:
            return False

    return plugin_instance
