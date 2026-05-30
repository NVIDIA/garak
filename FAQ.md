# garak LLM probe: Frequently Asked Questions


## How do I pronounce garak?

Good question! Emphasis on the first bit, GA-rak. 

Both 'a's like a in English "hat", or à in French, or /æ/ in IPA.

## What's this tool for?

`garak` is designed to help discover situations where a language model generates outputs that one might not want it to. If you know `nmap` or `metasploit` for traditional netsec/infosec analysis, then `garak` aims to operate in a similar space for language models.

It's not a tool for assessing social biases in language models, or propensity of a system to produce toxic content. The focus isn't safety, it's security. `garak` might try to exploit a weakness and demonstrate that weakness by making a model generate unsafe content, but we're focused on the weakness over the content.

## How does garak work?

`garak` has probes that try to look for different "vulnerabilities". Each probs sends specific prompts to models, and gets multiple generations for each prompt. LLM output is often stochastic, so a single test isn't very informative. These generations are then processed by "detectors", which will look for "hits". If a detector registers a hit, that attempt is registered as failing. Finally, a report is output with the success/failure rate for each probe and detector.

## Do these results have scientific validity?

No. The scores from any probe don't operate on any kind of normalised scale. Higher passing percentage is better, but that's it. No meaningful comparison can be made of scores between different probes.

## How does it determine a pass/fail score for replies?

Each detector is different. Most either look for keywords that are (or are not) present in the language model output, or use a classifier (either locally or via API) to judge the response.

## Does garak allow for additional prompts ?

Additional prompts can be probed by creating a new plugin -- this isn't as tough as it sounds; take a look at the modules in the `garak/probes/` directory for inspiration.

## How will a auditor know what was used in testing?

The JSONL report created for each run includes language model parameters, all the prompts sent to the mode, all the model responses, and also the mapping between these and evaluation scores. There's a JSONL report analysis script in `analyse/analyse_log.py`.

## Do you have plans to setup an environment for running these tests on HuggingFace?

Not immediately, but if you have the Gradio skills, get in touch!

## Can you add support for vulnerability X?

Perhaps - please [open an issue](https://github.com/NVIDIA/garak/issues/new), including a description of the vulnerability, example prompts, and tag it "new plugin" and "probes".

## Can you add support for model X?

Would love to! Please [open an issue](https://github.com/NVIDIA/garak/issues/new), tagging it "new plugin" and "generators".

## How much disk space do I need to run garak?

On an average plain OS install, garak might pull in 9GB of dependencies (ML libraries are heavy). If you're running a model locally, enough space will be required for that model plus its dependencies, too - check out the model's files for an estimate.  Hugging Face gpt2 is about 5GB (https://huggingface.co/google/gemma-2-2b-it/tree/main), whereas Hugging Face Llama-3.1-405B is around half a terabyte (https://huggingface.co/meta-llama/Meta-Llama-3.1-405B/tree/main). Garak sometimes uses machine learning-based detectors, but we go for smaller variants, so I'd guess/hope under 2GB. Finally, logs generated while running can be up to 60MB per standard run - ymmv!

Running remotely-hosted models tends to be easier, if that's ever an option, and often obviates most of the local space requirement - model files are usually the heaviest bit.

## Are there instructions for Hugging Face gated models?

Gated models simply require login and in some case acceptance of model provider license terms. [Here](https://huggingface.co/docs/huggingface_hub/en/guides/cli) are details of huggingface-cli login process.

## Is it safe to build garak into toolchains? Who's supporting this?

NVIDIA Corporation officially contributes to the garak open-source project and will continue to do so in the long term. Garak will continue to be licensed with Apache 2.0. Get in touch if you'd like to talk more about this.

## Can an LLM have vulnerabilities?

The things garak probes for are generally not like traditional cybersec vulnerabilities. LLM model parameters don't and can't have vulnerabilities themselves; it's just data. What most of the probes in garak check for are whether or not a model can be made to behave unexpectedly at inference time, by breaking its alignment or output policy, using exploits. The DHS calls some of these behaviours "weaknesses"; see e.g. [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) for prompt injection. 

Some garak probes still check for traditional cybersecurity vulnerabilities within the scope of what can be extracted from APIs also used for inference.

## I tried to scan a model from HuggingFace, but for some reason, the process got killed when loading checkpoint shards. I ran the scan in my Jupyter notebook locally, the model had already been downloaded during a previous run. I couldn't get past 75% without the process being killed. 

This sounds like hitting a resource limit - something external to garak, e.g. the kernel, has taken action. Does your process have access to the required system RAM and GPU memory

## How can I use garak to scan a NIM of an LLM?  What should the "model_type" be? And how do we pass the NIM endpoint url to garak?

`model_type` should be "nim" for chat-type models (which is most of them - this selects the right class automatically. Then, set model_name to [organisation]/[model name] from [build.nvidia.com](https://build.nvidia.com) (the JSON example is authoritative). For example, `--model_type nim --model_name meta/llama-3.1-8b-instruct`. You will need to put the API key in the `NIM_API_KEY` environment variable, or in the config.

## If I have already scanned a model on HuggingFace, and I use the same model somewhere else, say in a container, is it necessary for me to scan the container with garak as well?

No, if the model is the same, you should get the same results - though there are some probes that scan the model files themself, which work on Hugging Face but not via a container.

## How can I scan a RAG pipeline with garak?

Currently, the major attack we hear about in RAG systems is indirect prompt injection, and garak already scans for a few of those.

## There are so many probes in garak, I was trying to scan a model for all probes, but it took hours and I eventually had to kill that scan. What is the recommended practice on scanning a model? Which typical probes are recommended?

Recommended practice: it's really context dependent. The builtin "fast" config works pretty well (`--config fast`). It's also useful to run with `--parallel_attempts` (using a value of e.g. 20 or 40) if the model isn't local.

## Once a model is scanned, there is really no need to scan it again for the same probe(s) unless the model has been customized/finetuned?

We update garak by improving existing probes or adding new ones quite frequently, and so scores will go down over time - garak isn't a benchmark, and the more we learn about failures in LLMs, the harder garak gets. But if you're looking at a short period of just a month or two, then the scores will probably stay pretty much the same. We do not recommend relying on scores over six months old.

## How can I create my own generator?

Adding a custom generator is fairly straight forward. One can either add a new class in the existing module, or a new module in the `generators/` directory with a class that extends garak.generators.base.Generator that will be loaded at runtime. The reference documentation has a [full guide to creating garak generators](https://reference.garak.ai/en/latest/contributing.generator.html).

## How can I redirect `garak_runs/` and `garak.log` to another place instead of `~/.local/share/garak/`?

* `garak_runs` is configured via top-level config param `reporting.report_dir` and also CLI argument `--report_prefix` (which currently can include directory separator characters, so an absolute path can be given)
* An example of the location of the config param can be seen in https://github.com/NVIDIA/garak/blob/main/garak/resources/garak.core.yaml
* If `reporting.report_dir` is set to an absolute path, you can move it anywhere
* If it's a relative path, it will be within the garak directory under the "data" directory following the cross-platform [XDG base directory specification](https://specifications.freedesktop.org/basedir-spec/latest/) for local storage
* There's no CLI or config option for moving `garak.log`, which is also stored in the XDG data directory
* We would welcome a PR implementing configurability of logfile path
* The Python implementation of XDG that garak uses allows overriding the data directory using the `XDG_DATA_HOME` environment variable
* An alternative is to symlink the paths to where you want them to be

## How do I configure my run in more detail?

There is a lot you can do here. In order of increasing complexity:

1. Be specific about the list of probes you request, using the `-p` command line option
1. Have a look at `garak`'s config options: run `garak --help` to see what there is
1. Garak offers rich and detailed configuration for runs and its plugins, via YAML. You can find an intro guide here, [Configuring garak](https://reference.garak.ai/en/latest/configurable.html).

## There are many static prompts in garak. How can I make these more dynamic?

This is exactly what [`buffs`](https://reference.garak.ai/en/latest/buffs.html) are for - buffs automatically
modify prompts in flight before they're sent to the generator/LLM. For example, `garak.buffs.paraphrase`
dynamically converts each query prompt into a set of alternative phrasings - given a fixed inference budget, it's often great alternative to increasing generations (docs [here](https://reference.garak.ai/en/latest/garak.buffs.paraphrase.html)).

## Is garak just static probes?

No, very much not. Garak has:

* static probes, which are a set of fixed prompts; this can be from e.g. scientific papers that specify a fixed set of prompts, so that we get replicability
* assembled probes, where prompts are assembled from a configurable set of pieces
* dynamic probes, which look different each run; an example is `latentinjection.LatentWhoisSnippet`, where the list of snippet permutations is so large that it's best to shuffe and sample
* reactive probes, that respond to LLM behavior and adapt as we go along; examples include `atkgen`, `topic`, as well as the compute-intense `tap` and `suffix` modules (excluding their cached versions)

## How do I get a report according to OWASP LLM Top 10 categories?

You can invoke report analysis directly on the report.jsonl file in question,
and give a taxonomy as a second parameter. For example:

```
python -m garak.analyze.report_digest garak.1234.report.jsonl owasp > report.html
```

This groups the top-leve figures and findings according to the OWASP Top 10 for LLM v1.


## How do I interpret my scores?

It's difficult to know if a 0.55 pass rate is good or terrible. That's why we calibrate
garak scores against a bag of state-of-the-art models regularly, and report how well the
target model is performing relative to that. It's included in the HTML report as a Z-score,
and can be given on the CLI by setting `system.show_z=True` in the config.

For more details on exactly how we do this calibration, see [data/calibration/bag.md].



<!-- ## Why the name?

Congrats, if you're reading this, you found a flag!

It's also a smooth-talking, manipulative, persuasive, well-written character from a nineties TV series. Because we need tools like that in order to dissect LLM behavior. -->
