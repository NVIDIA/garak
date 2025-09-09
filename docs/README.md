# Documentation

## Building the Documentation

1. Install dependencies:

   ```console
   python3 -m pip install -r requirements.txt
   python3 -m pip install -r docs/requirements-docs.txt
   ```

1. Build the documentation:

   ```console
   make -C docs/source doc
   ```

   The HTML is created in the `docs/source/html` directory.
