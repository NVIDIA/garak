import pytest
import os

# suppress all logging unless location defined in ENV
if os.getenv("GARAK_LOG_FILE", None) is None:
    os.environ["GARAK_LOG_FILE"] = str(os.devnull)

from garak import _config, _plugins

# force a local cache file to exist when this top level import is loaded
if not os.path.isfile(_plugins.PluginCache._user_plugin_cache_filename):
    _plugins.PluginCache.instance()


@pytest.fixture(autouse=True)
def config_report_cleanup(request):
    """Cleanup a testing and report directory once we are finished."""

    def remove_log_files():
        files = []
        if _config.transient.reportfile is not None:
            _config.transient.reportfile.close()
            report_html_file = _config.transient.report_filename.replace(
                ".jsonl", ".html"
            )
            hitlog_file = _config.transient.report_filename.replace(
                ".report.", ".hitlog."
            )
            files.append(_config.transient.report_filename)
            files.append(report_html_file)
            files.append(hitlog_file)

        for file in files:
            if os.path.exists(file):
                os.remove(file)

    def clear_plugin_instances():
        with _plugins.PluginProvider._mutex:
            _plugins.PluginProvider._instance_cache = {}

    request.addfinalizer(remove_log_files)
    request.addfinalizer(clear_plugin_instances)
