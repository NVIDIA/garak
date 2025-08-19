garak._plugins
==============


garak._plugins
--------------

This module manages plugin enumeration and loading.
There is one class per plugin in ``garak``.
Enumerating the classes, with e.g. ``--list_probes`` on the command line, means importing each module.
Therefore, modules should do as little as possible on load, and delay
intensive activities (like loading classifiers) until a plugin's class is instantiated.


Code
^^^^


.. automodule:: garak._plugins
   :members:
   :undoc-members:
   :show-inheritance:
