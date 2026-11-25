# garak, LLM vulnerability scanner

*Generative AI Red-teaming & Assessment Kit*

`garak` checks if an LLM-backed application can be made to fail in a way we don't want. It has more than 190 probes and growing, covering hallucination, data leakage, prompt injection, misinformation, toxicity generation, jailbreaks, and many other weaknesses. If you know `nmap` or `msf` / Metasploit Framework, garak does somewhat similar things.

`garak` works with anything from a bare model to a full application with guardrails and tools around it. It combines static, dynamic, and adaptive probes.

`garak`'s a free tool. We love developing it and are always interested in adding functionality to support applications. 

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests/Linux](https://github.com/NVIDIA/garak/actions/workflows/test_linux.yml/badge.svg)](https://github.com/NVIDIA/garak/actions/workflows/test_linux.yml)
[![Tests/Windows](https://github.com/NVIDIA/garak/actions/workflows/test_windows.yml/badge.svg)](https://github.com/NVIDIA/garak/actions/workflows/test_windows.yml)
[![Tests/OSX](https://github.com/NVIDIA/garak/actions/workflows/test_macos.yml/badge.svg)](https://github.com/NVIDIA/garak/actions/workflows/test_macos.yml)
[![Documentation Status](https://readthedocs.org/projects/garak/badge/?version=latest)](https://reference.garak.ai/)
[![arXiv](https://img.shields.io/badge/cs.CL-arXiv%3A2406.11036-b31b1b.svg)](https://arxiv.org/abs/2406.11036)
[![discord-img](https://img.shields.io/badge/chat-on%20discord-yellow.svg)](https://discord.gg/uVch4puUCs)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/garak)](https://pypi.org/project/garak)
[![PyPI](https://badge.fury.io/py/garak.svg)](https://badge.fury.io/py/garak)
[![Downloads](https://static.pepy.tech/badge/garak)](https://pepy.tech/project/garak)
[![Downloads](https://static.pepy.tech/badge/garak/month)](https://pepy.tech/project/garak)


## Get started
### > User guide: [reference.garak.ai](https://reference.garak.ai/)
### > Discord: [discord.gg/uVch4puUCs](https://discord.gg/uVch4puUCs)
### > Project links & home: [garak.ai](https://garak.ai/)
### > Twitter: [@garak_llm](https://twitter.com/garak_llm)
### > DEF CON talk: [slides](https://reference.garak.ai/en/latest/_static/garak_aiv_slides.pdf)

<hr>

## How garak works

`garak` is built from a few kinds of plugins:
* [generators](https://reference.garak.ai/en/latest/index_generators.html) connect `garak` to the system you're testing
* [probes](https://reference.garak.ai/en/latest/index_probes.html) send prompts designed to make it fail
* [detectors](https://reference.garak.ai/en/latest/index_detectors.html) check each response for the failure a probe is looking for
* [buffs](https://reference.garak.ai/en/latest/index_buffs.html) change prompts before they're sent, for example by encoding, paraphrasing or translating them
* [harnesses](https://reference.garak.ai/en/latest/index_harnesses.html) run probes and detectors together, and [evaluators](https://reference.garak.ai/en/latest/index_evaluators.html) score the results

## LLM support

currently supports:
* **local models:** Hugging Face, Ollama, gguf via llama.cpp
* **model APIs:** OpenAI and OpenAI-compatible APIs, Anthropic, Azure OpenAI, AWS Bedrock, Cohere, Groq, Mistral, NVIDIA NIM, IBM watsonx, Replicate
* **frameworks:** LiteLLM, LangChain, NeMo Guardrails, Rasa, `llm`
* **agents and apps:** REST and WebSocket endpoints, LangChain Serve, Python functions

## Install:

`garak` is a command-line tool. It runs on Linux, macOS and Windows.

### Standard install with `pip`

Just grab it from PyPI and you should be good to go:

```
python -m pip install -U garak
```

### Install development version with `pip`

The standard pip version of `garak` is updated periodically. To get a fresher version from GitHub, try:

```
python -m pip install -U git+https://github.com/NVIDIA/garak.git@main
```

### Clone from source

`garak` has its own dependencies. You can to install `garak` in its own Conda environment:

```
conda create --name garak "python>=3.11,<=3.14"
conda activate garak
gh repo clone NVIDIA/garak
cd garak
python -m pip install -e .
```

OK, if that went fine, you're probably good to go!

**Note**: if you cloned before the move to the `NVIDIA` GitHub organisation, but you're reading this at the `github.com/NVIDIA` URI, please update your remotes as follows:

```
git remote set-url origin https://github.com/NVIDIA/garak.git
```


## Getting started

The general syntax is:

`garak <options>`

`garak` needs to know what target to scan, and by default, it'll try all the active probes it knows on that target, using the vulnerability detectors recommended by each probe. You can see a list of probes, with inactive ones marked 💤, using:

`garak --list_probes`

To specify a generator, use the `--target_type` and, optionally, the `--target_name` options. Target type specifies a generator family/interface; target name specifies the exact model or endpoint to be used. The "Intro to generators" section below describes some of the generators supported. A straightforward generator family is Hugging Face models; to load one of these, set `--target_type` to `huggingface` and `--target_name` to the model's name on Hub (e.g. `"RWKV/rwkv-4-169m-pile"`). Some generators might need an API key to be set as an environment variable, and they'll let you know if they need that.

`garak` runs all active probes by default, but you can be specific about that too. `--spec probes.promptinject` will use only the [PromptInject](https://github.com/agencyenterprise/promptinject) framework's methods, for example. You can also specify one specific plugin instead of a plugin family by adding the plugin name after a `.`; for example, `--spec probes.lmrc.SlurUsage` will use an implementation of checking for models generating slurs based on the [Language Model Risk Cards](https://arxiv.org/abs/2303.18190) framework.

For help and inspiration, find us on [Twitter](https://twitter.com/garak_llm) or [discord](https://discord.gg/uVch4puUCs)!

## Examples

Probe a commercial model for encoding-based prompt injection (macOS/Linux) (replace example value with a real OpenAI API key)
 
```
export OPENAI_API_KEY="sk-123XXXXXXXXXXXX"
python3 -m garak --target_type openai --target_name gpt-5-nano --spec probes.encoding
```

See if the Hugging Face version of GPT2 is vulnerable to DAN 11.0

```
python3 -m garak --target_type huggingface --target_name gpt2 --spec probes.dan.Dan_11_0
```


## Reading the results

For each probe loaded, garak will print a progress bar as it generates. Once generation is complete, a row evaluating that probe's results on each detector is given. If any of the prompt attempts yielded an undesirable behavior, the response will be marked as FAIL, and the failure rate given.

Here are the results with the `encoding` module on a GPT-3 variant:
![alt text](https://i.imgur.com/8Dxf45N.png)

And the same results for ChatGPT:
![alt text](https://i.imgur.com/VKAF5if.png)

We can see that the more recent model is much more susceptible to encoding-based injection attacks, where text-babbage-001 was only found to be vulnerable to quoted-printable and MIME encoding injections.  The figures at the end of each row, e.g. 840/840, indicate how many text generations seemed to behave OK, and then the total. The figure can be quite high because more than one generation is made per prompt - by default, 5.

Errors go in `garak.log`; the run is logged in detail in a `.jsonl` file specified at analysis start & end. There's a basic analysis script in `garak/analyze/analyze_log.py` which will output the probes and prompts that led to the most hits.

Send PRs & open issues. Happy hunting!

## Intro to generators

Some common setups:
* **Hugging Face model, run locally:** `--target_type huggingface --target_name gpt2`
* **Ollama:** `--target_type ollama --target_name llama3.2`, with Ollama running on its default port
* **gguf model with llama.cpp:** `--target_type ggml --target_name /path/to/model.gguf`, with the path to your llama.cpp executable in `GGML_MAIN_PATH`
* **OpenAI:** `--target_type openai --target_name gpt-5-nano`, with your key in `OPENAI_API_KEY`
* **NVIDIA NIM:** `--target_type nim --target_name meta/llama-3.1-8b-instruct`, with your key in `NIM_API_KEY`
* **AWS Bedrock:** `--target_type bedrock --target_name claude-3-sonnet`, with your key in `BEDROCK_API_KEY`
* **any REST endpoint:** `--target_type rest`, described in a short YAML file; see the [REST generator docs](https://reference.garak.ai/en/latest/garak.generators.rest.html)
* **testing without a model:** `--target_type test.Blank` returns empty output, and `test.Repeat` echoes the prompt back

The [generator reference](https://reference.garak.ai/en/latest/index_generators.html) covers every generator and its options.

## Intro to probes

Probes are grouped into modules by the kind of weakness they look for. Some examples:
* **jailbreaks:** `dan`, `tap`, `goat`, `fitd`, `grandma`, `phrasing`
* **prompt injection:** `promptinject`, `latentinjection`, `encoding`
* **data leakage:** `leakreplay`, `divergence`, `propile`, `sysprompt_extraction`
* **harmful content:** `realtoxicityprompts`, `lmrc`, `donotanswer`, `malwaregen`
* **misinformation and hallucination:** `misleading`, `snowball`, `packagehallucination`
* **attacks on downstream systems:** `web_injection`, `exploitation`, `ansiescape`
* **agents and multimodal:** `agent_breaker`, `visual_jailbreak`, `audio`

Each probe is also tagged with the risks and techniques it covers, from the OWASP LLM Top 10, AVID, CWE, the EU AI Act and the red-teaming techniques in [Summon a Demon and Bind It](https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0314658). Run probes by tag with `--spec`, e.g. `--spec tag:owasp:llm01`, and group results by a taxonomy with `--taxonomy`, e.g. `--taxonomy owasp`. The [tags page](https://reference.garak.ai/en/latest/tags_taxonomies.html) lists them all.

Run `garak --list_probes` to list every probe, and the [probe reference](https://reference.garak.ai/en/latest/index_probes.html) describes each one.

## Logging

`garak` generates multiple kinds of log:
* A log file, `garak.log`. This includes debugging information from `garak` and its plugins, and is continued across runs.
* A report of the current run, structured as JSONL. A new report file is created every time `garak` runs. The name of this file is output at the beginning and, if successful, also at the end of the run. In the report, an entry is made for each probing attempt both as the generations are received, and again when they are evaluated; the entry's `status` attribute takes a constant from `garak.attempts` to describe what stage it was made at.
* A hit log, detailing attempts that yielded a vulnerability (a 'hit')

## How is the code structured?

Check out the [reference docs](https://reference.garak.ai/) for an authoritative guide to `garak` code structure.

Each kind of plugin from [How garak works](#how-garak-works) has its own directory of modules, and each module provides a number of classes that act as individual plugins.

* `garak/probes/` - classes for generating interactions with LLMs
* `garak/detectors/` - classes for detecting an LLM is exhibiting a given failure mode
* `garak/evaluators/` - assessment reporting schemes
* `garak/generators/` - plugins for LLMs to be probed
* `garak/harnesses/` - classes for structuring testing
* `garak/buffs/` - classes for changing prompts before they're sent
* `garak/resources/` - ancillary items required by plugins

The default operating mode is to use the `probewise` harness. Given a list of probe module names and probe plugin names, the `probewise` harness instantiates each probe, then for each probe reads its `primary_detector` and `extended_detectors` attributes to get a list of `detector`s to run on the output.

Each plugin category (`probes`, `detectors`, `evaluators`, `generators`, `harnesses`, `buffs`) includes a `base.py` which defines the base classes usable by plugins in that category. Each plugin module defines plugin classes that inherit from one of the base classes. For example, `garak.generators.openai.OpenAIGenerator` descends from `garak.generators.base.Generator`.

Larger artefacts, like model files and bigger corpora, are kept out of the repository; they can be stored on e.g. Hugging Face Hub and loaded locally by clients using `garak`.


## Developing your own plugin

* Take a look at how other plugins do it
* Inherit from one of the base classes, e.g. `garak.probes.base.TextProbe`
* Override as little as possible
* You can test the new code in at least two ways:
  * Start an interactive Python session
    * Import the model, e.g. `import garak.probes.mymodule`
    * Instantiate the plugin, e.g. `p = garak.probes.mymodule.MyProbe()`
  * Run a scan with test plugins
    * For probes, try a blank generator and always.Pass detector: `python3 -m garak -t test.Blank -S probes.mymodule -d always.Pass`
    * For detectors, try a blank generator and a blank probe: `python3 -m garak -t test.Blank -S probes.test.Blank -d mymodule`
    * For generators, try a blank probe and always.Pass detector: `python3 -m garak -t mymodule -S probes.test.Blank -d always.Pass`
  * Get `garak` to list all the plugins of the type you're writing, with `--list_probes`, `--list_detectors`, or `--list_generators`


## FAQ

We have an FAQ [here](https://github.com/NVIDIA/garak/blob/main/FAQ.md). Reach out if you have any more questions! [garak@nvidia.com](mailto:garak@nvidia.com)

Code reference documentation is at [reference.garak.ai](https://reference.garak.ai/).

## Citing garak

You can read the [garak paper on arXiv](https://arxiv.org/abs/2406.11036). If you use garak, please cite us.

```
@misc{garak,
  title={{garak: A Framework for Security Probing Large Language Models}},
  author={Leon Derczynski and Erick Galinkin and Jeffrey Martin and Subho Majumdar and Nanna Inie},
  year={2024},
  eprint={2406.11036},
  archivePrefix={arXiv},
  primaryClass={cs.CL},
  url={https://arxiv.org/abs/2406.11036}
}
```

<hr>

_"Lying is a skill like any other, and if you wish to maintain a level of excellence you have to practice constantly"_ - Elim

For updates and news see [@garak_llm](https://twitter.com/garak_llm)

© 2023- Leon Derczynski; Apache license v2, see [LICENSE](LICENSE)
