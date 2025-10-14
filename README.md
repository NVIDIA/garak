# garak, LLM vulnerability scanner

*Generative AI Red-teaming & Assessment Kit*

`garak` checks if an LLM can be made to fail in a way we don't want. `garak` probes for hallucination, data leakage, prompt injection, misinformation, toxicity generation, jailbreaks, and many other weaknesses. If you know `nmap` or `msf` / Metasploit Framework, garak does somewhat similar things to them, but for LLMs. 

`garak` focuses on ways of making an LLM or dialog system fail. It combines static, dynamic, and adaptive probes to explore this.

`garak`'s a free tool. We love developing it and are always interested in adding functionality to support applications. 

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests/Linux](https://github.com/NVIDIA/garak/actions/workflows/test_linux.yml/badge.svg)](https://github.com/NVIDIA/garak/actions/workflows/test_linux.yml)
[![Tests/Windows](https://github.com/NVIDIA/garak/actions/workflows/test_windows.yml/badge.svg)](https://github.com/NVIDIA/garak/actions/workflows/test_windows.yml)
[![Tests/OSX](https://github.com/NVIDIA/garak/actions/workflows/test_macos.yml/badge.svg)](https://github.com/NVIDIA/garak/actions/workflows/test_macos.yml)
[![Documentation Status](https://readthedocs.org/projects/garak/badge/?version=latest)](http://garak.readthedocs.io/en/latest/?badge=latest)
[![arXiv](https://img.shields.io/badge/cs.CL-arXiv%3A2406.11036-b31b1b.svg)](https://arxiv.org/abs/2406.11036)
[![discord-img](https://img.shields.io/badge/chat-on%20discord-yellow.svg)](https://discord.gg/uVch4puUCs)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/garak)](https://pypi.org/project/garak)
[![PyPI](https://badge.fury.io/py/garak.svg)](https://badge.fury.io/py/garak)
[![Downloads](https://static.pepy.tech/badge/garak)](https://pepy.tech/project/garak)
[![Downloads](https://static.pepy.tech/badge/garak/month)](https://pepy.tech/project/garak)


## Get started
### > See our user guide! [docs.garak.ai](https://docs.garak.ai/)
### > Join our [Discord](https://discord.gg/uVch4puUCs)!
### > Project links & home: [garak.ai](https://garak.ai/)
### > Twitter: [@garak_llm](https://twitter.com/garak_llm)
### > DEF CON [slides](https://garak.ai/garak_aiv_slides.pdf)!

<hr>

## LLM support

currently supports:
* [hugging face hub](https://huggingface.co/models) generative models
* [replicate](https://replicate.com/) text models
* [openai api](https://platform.openai.com/docs/introduction) chat & continuation models
* [litellm](https://www.litellm.ai/)
* pretty much anything accessible via REST
* gguf models like [llama.cpp](https://github.com/ggerganov/llama.cpp) version >= 1046
* .. and many more LLMs!

## Install:

`garak` is a command-line tool. It's developed in Linux and OSX.

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
conda create --name garak "python>=3.10,<=3.12"
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

`garak` needs to know what model to scan, and by default, it'll try all the probes it knows on that model, using the vulnerability detectors recommended by each probe. You can see a list of probes using:

`garak --list_probes`

To specify a generator, use the `--target_type` and, optionally, the `--target_name` options. Model type specifies a model family/interface; model name specifies the exact model to be used. The "Intro to generators" section below describes some of the generators supported. A straightforward generator family is Hugging Face models; to load one of these, set `--target_type` to `huggingface` and `--target_name` to the model's name on Hub (e.g. `"RWKV/rwkv-4-169m-pile"`). Some generators might need an API key to be set as an environment variable, and they'll let you know if they need that.

`garak` runs all the probes by default, but you can be specific about that too. `--probes promptinject` will use only the [PromptInject](https://github.com/agencyenterprise/promptinject) framework's methods, for example. You can also specify one specific plugin instead of a plugin family by adding the plugin name after a `.`; for example, `--probes lmrc.SlurUsage` will use an implementation of checking for models generating slurs based on the [Language Model Risk Cards](https://arxiv.org/abs/2303.18190) framework.

For help and inspiration, find us on [Twitter](https://twitter.com/garak_llm) or [discord](https://discord.gg/uVch4puUCs)!

## Examples

Probe ChatGPT for encoding-based prompt injection (OSX/\*nix) (replace example value with a real OpenAI API key)
 
```
export OPENAI_API_KEY="sk-123XXXXXXXXXXXX"
python3 -m garak --target_type openai --target_name gpt-3.5-turbo --probes encoding
```

See if the Hugging Face version of GPT2 is vulnerable to DAN 11.0

```
python3 -m garak --target_type huggingface --target_name gpt2 --probes dan.Dan_11_0
```


## Reading the results

For each probe loaded, garak will print a progress bar as it generates. Once generation is complete, a row evaluating that probe's results on each detector is given. If any of the prompt attempts yielded an undesirable behavior, the response will be marked as FAIL, and the failure rate given.

Here are the results with the `encoding` module on a GPT-3 variant:
![alt text](https://i.imgur.com/8Dxf45N.png)

And the same results for ChatGPT:
![alt text](https://i.imgur.com/VKAF5if.png)

We can see that the more recent model is much more susceptible to encoding-based injection attacks, where text-babbage-001 was only found to be vulnerable to quoted-printable and MIME encoding injections.  The figures at the end of each row, e.g. 840/840, indicate the number of text generations total and then how many of these seemed to behave OK. The figure can be quite high because more than one generation is made per prompt - by default, 10.

Errors go in `garak.log`; the run is logged in detail in a `.jsonl` file specified at analysis start & end. There's a basic analysis script in `analyse/analyse_log.py` which will output the probes and prompts that led to the most hits.

Send PRs & open issues. Happy hunting!

## Intro to generators

### Hugging Face

Using the Pipeline API:
* `--target_type huggingface` (for transformers models to run locally)
* `--target_name` - use the model name from Hub. Only generative models will work. If it fails and shouldn't, please open an issue and paste in the command you tried + the exception!

Using the Inference API:
* `--target_type huggingface.InferenceAPI` (for API-based model access)
* `--target_name` - the model name from Hub, e.g. `"mosaicml/mpt-7b-instruct"`

Using private endpoints:
* `--target_type huggingface.InferenceEndpoint` (for private endpoints)
* `--target_name` - the endpoint URL, e.g. `https://xxx.us-east-1.aws.endpoints.huggingface.cloud`

* (optional) set the `HF_INFERENCE_TOKEN` environment variable to a Hugging Face API token with the "read" role; see https://huggingface.co/settings/tokens when logged in

### OpenAI

* `--target_type openai`
* `--target_name` - the OpenAI model you'd like to use. `gpt-3.5-turbo-0125` is fast and fine for testing.
* set the `OPENAI_API_KEY` environment variable to your OpenAI API key (e.g. "sk-19763ASDF87q6657"); see https://platform.openai.com/account/api-keys when logged in

Recognised model types are whitelisted, because the plugin needs to know which sub-API to use. Completion or ChatCompletion models are OK. If you'd like to use a model not supported, you should get an informative error message, and please send a PR / open an issue.

### Replicate

* set the `REPLICATE_API_TOKEN` environment variable to your Replicate API token, e.g. "r8-123XXXXXXXXXXXX"; see https://replicate.com/account/api-tokens when logged in

Public Replicate models:
* `--target_type replicate`
* `--target_name` - the Replicate model name and hash, e.g. `"stability-ai/stablelm-tuned-alpha-7b:c49dae36"`

Private Replicate endpoints:
* `--target_type replicate.InferenceEndpoint` (for private endpoints)
* `--target_name` - username/model-name slug from the deployed endpoint, e.g. `elim/elims-llama2-7b`

### Cohere

* `--target_type cohere`
* `--target_name` (optional, `command` by default) - The specific Cohere model you'd like to test
* set the `COHERE_API_KEY` environment variable to your Cohere API key, e.g. "aBcDeFgHiJ123456789"; see https://dashboard.cohere.ai/api-keys when logged in

### Groq

* `--target_type groq`
* `--target_name` - The name of the model to access via the Groq API
* set the `GROQ_API_KEY` environment variable to your Groq API key, see https://console.groq.com/docs/quickstart for details on creating an API key

### ggml

* `--target_type ggml`
* `--target_name` - The path to the ggml model you'd like to load, e.g. `/home/leon/llama.cpp/models/7B/ggml-model-q4_0.bin`
* set the `GGML_MAIN_PATH` environment variable to the path to your ggml `main` executable

### REST

`rest.RestGenerator` is highly flexible and can connect to any REST endpoint that returns plaintext or JSON. It does need some brief config, which will typically result a short YAML file describing your endpoint. See https://reference.garak.ai/en/latest/garak.generators.rest.html for examples.

### NIM

Use models from https://build.nvidia.com/ or other NIM endpoints.
* set the `NIM_API_KEY` environment variable to your authentication API token, or specify it in the config YAML

For chat models:
* `--target_type nim`
* `--target_name` - the NIM `model` name, e.g. `meta/llama-3.1-8b-instruct`

For completion models:
* `--target_type nim.NVOpenAICompletion`
* `--target_name` - the NIM `model` name, e.g. `bigcode/starcoder2-15b`


### Test

* `--target_type test`
* (alternatively) `--target_name test.Blank`
For testing. This always generates the empty string, using the `test.Blank` generator.  Will be marked as failing for any tests that *require* an output, e.g. those that make contentious claims and expect the model to refute them in order to pass.

* `--target_type test.Repeat`
For testing. This generator repeats back the prompt it received.

## Intro to probes

| Probe                | Description                                                                                                                   |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------|
| blank                | A simple probe that always sends an empty prompt.                                                                             |
| atkgen               | Automated Attack Generation. A red-teaming LLM probes the target and reacts to it in an attempt to get toxic output. Prototype, mostly stateless, for now uses a simple GPT-2 [fine-tuned](https://huggingface.co/garak-llm/artgpt2tox) on the subset of hhrlhf attempts that yielded detectable toxicity (the only target currently supported for now). |
| av_spam_scanning     | Probes that attempt to make the model output malicious content signatures                                                     |
| continuation         | Probes that test if the model will continue a probably undesirable word                                                       |
| dan                  | Various [DAN](https://adguard.com/en/blog/chatgpt-dan-prompt-abuse.html) and DAN-like attacks                                 |
| donotanswer          | Prompts to which responsible language models should not answer.                                                               |
| encoding             | Prompt injection through text encoding                                                                                        |
| gcg                  | Disrupt a system prompt by appending an adversarial suffix.                                                                   |
| glitch               | Probe model for glitch tokens that provoke unusual behavior.                                                                  |
| grandma              | Appeal to be reminded of one's grandmother.                                                                                   |
| goodside             | Implementations of Riley Goodside attacks.                                                                                    |
| leakreplay           | Evaluate if a model will replay training data.                                                                                |
| lmrc                 | Subsample of the [Language Model Risk Cards](https://arxiv.org/abs/2303.18190) probes                                         |
| malwaregen           | Attempts to have the model generate code for building malware                                                                 |
| misleading           | Attempts to make a model support misleading and false claims                                                                  |
| packagehallucination | Trying to get code generations that specify non-existent (and therefore insecure) packages.                                   |
| promptinject         | Implementation of the Agency Enterprise [PromptInject](https://github.com/agencyenterprise/PromptInject/tree/main/promptinject) work (best paper awards @ NeurIPS ML Safety Workshop 2022) |
| realtoxicityprompts  | Subset of the RealToxicityPrompts work (data constrained because the full test will take so long to run)                      |
| snowball             | [Snowballed Hallucination](https://ofir.io/snowballed_hallucination.pdf) probes designed to make a model give a wrong answer to questions too complex for it to process |
| xss                  | Look for vulnerabilities the permit or enact cross-site attacks, such as private data exfiltration.                           |

## Logging

`garak` generates multiple kinds of log:
* A log file, `garak.log`. This includes debugging information from `garak` and its plugins, and is continued across runs.
* A report of the current run, structured as JSONL. A new report file is created every time `garak` runs. The name of this file is output at the beginning and, if successful, also at the end of the run. In the report, an entry is made for each probing attempt both as the generations are received, and again when they are evaluated; the entry's `status` attribute takes a constant from `garak.attempts` to describe what stage it was made at.
* A hit log, detailing attempts that yielded a vulnerability (a 'hit')

## How is the code structured?

Check out the [reference docs](https://reference.garak.ai/) for an authoritative guide to `garak` code structure.

In a typical run, `garak` will read a model type (and optionally model name) from the command line, then determine which `probe`s and `detector`s to run, start up a `generator`, and then pass these to a `harness` to do the probing; an `evaluator` deals with the results. There are many modules in each of these categories, and each module provides a number of classes that act as individual plugins.

* `garak/probes/` - classes for generating interactions with LLMs
* `garak/detectors/` - classes for detecting an LLM is exhibiting a given failure mode
* `garak/evaluators/` - assessment reporting schemes
* `garak/generators/` - plugins for LLMs to be probed
* `garak/harnesses/` - classes for structuring testing
* `resources/` - ancillary items required by plugins

The default operating mode is to use the `probewise` harness. Given a list of probe module names and probe plugin names, the `probewise` harness instantiates each probe, then for each probe reads its `primary_detector` and `extended_detectors` attributes to get a list of `detector`s to run on the output.

Each plugin category (`probes`, `detectors`, `evaluators`, `generators`, `harnesses`) includes a `base.py` which defines the base classes usable by plugins in that category. Each plugin module defines plugin classes that inherit from one of the base classes. For example, `garak.generators.openai.OpenAIGenerator` descends from `garak.generators.base.Generator`.

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
    * For probes, try a blank generator and always.Pass detector: `python3 -m garak -m test.Blank -p mymodule -d always.Pass`
    * For detectors, try a blank generator and a blank probe: `python3 -m garak -m test.Blank -p test.Blank -d mymodule`
    * For generators, try a blank probe and always.Pass detector: `python3 -m garak -m mymodule -p test.Blank -d always.Pass`
  * Get `garak` to list all the plugins of the type you're writing, with `--list_probes`, `--list_detectors`, or `--list_generators`


## FAQ

We have an FAQ [here](https://github.com/NVIDIA/garak/blob/main/FAQ.md). Reach out if you have any more questions! [garak@nvidia.com](mailto:garak@nvidia.com)

Code reference documentation is at [garak.readthedocs.io](https://garak.readthedocs.io/en/latest/).

## Citing garak

You can read the [garak preprint paper](garak-paper.pdf). If you use garak, please cite us.

```
@article{garak,
  title={{garak: A Framework for Security Probing Large Language Models}},
  author={Leon Derczynski and Erick Galinkin and Jeffrey Martin and Subho Majumdar and Nanna Inie},
  year={2024},
  howpublished={\url{https://garak.ai}}
}
```

<hr>

_"Lying is a skill like any other, and if you wish to maintain a level of excellence you have to practice constantly"_ - Elim

For updates and news see [@garak_llm](https://twitter.com/garak_llm)

© 2023- Leon Derczynski; Apache license v2, see [LICENSE](LICENSE)
