# Documentation

## Building the Documentation

1. Install dependencies:

   From garak repository root: 

   ```console
   python3 -m pip install .
   python3 -m pip install -r docs/requirements-docs.txt
   ```

1. Build the documentation:

   ```console
   make -C docs/source doc
   ```

   The HTML is created in the `docs/source/html` directory.


## Publishing the Documentation

Tag the commit to publish with `docs-v<semver>`.

To avoid publishing the documentation as the latest, ensure the commit has `/not-latest` on a single line, tag that commit, and push to GitHub.
