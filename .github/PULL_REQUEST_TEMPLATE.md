Tell us what this change does. If you're fixing a bug, please mention
the github issue number.

Please ensure you are submitting **from a unique branch** in your repository to `main` upstream.

## Verification

List the steps needed to make sure this thing works

- [ ] Supporting configuration such as generator configuration file
``` json
{
    "huggingface": {
        "torch_type": "float32"
    }
}
```
- [ ] `garak -t <target_type> -n <model_name>`
- [ ] Run the tests and ensure they pass `python -m pytest tests/`
- [ ] ...
- [ ] **Verify** the thing does what it should
- [ ] **Verify** the thing does not do what it should not
- [ ] **Document** the thing and how it works ([Example](https://github.com/NVIDIA/garak/blob/61ce5c4ae3caac08e0abd1d069d223d8a66104bd/garak/generators/rest.py#L24-L100))

If you are opening a PR for a new plugin that targets a **specific** piece of hardware or requires a **complex or hard-to-find** testing environment, we recommend that you send us as much detail as possible.

Specific Hardware Examples:
* GPU related
  * Specific support required `cuda` / `mps` ( Please not `cuda` via `ROCm` if related )
  * Minium GPU Memory

Complex Software Examples:
* Expensive proprietary software
* Software with an extensive installation process
* Software without an English language UI
