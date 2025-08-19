# Interpreting results with a bag of models

Garak scores are interpreted compared to the state of the art. 
Using a bag of model results, we calibrate scores based on how those models perform on various probes and detectors.
The scores we get from the surveyed models are used to get a distribution of possible garak scores.
When surveying a target model, its pass rate is compared to the average and variation we see across state of the art models in order to estimate how well the target model is doing.

## What models go in the bag?

We look for the following things when composing the model bag for calibrating garak results:

* **Quantity** - There should be enough models in the bag to get usable results, and few enough to make running the experiments tractable
* **Recency** - Older models can give uncompetitive results, so we want recent ones. On the other hand, updating the bag very frequently makes it hard to compare results between garak runs.
* **Size** - We want models over a variety of sizes. Size is measured in parameter count, regardless of quantisation, and we look for models with 1-10B, 11-99B, and 100B+ parameters.
* **Provider** - No more than two models in the bag from the same provider
* **Openness** - Open weights models are easiest for us to survey, so we prefer to use those

## How do we use the results?

Each probe & detector pair yields an attack success rate / pass rate (pass rate = 1-ASR). We measure the pass rate for each of the detectors that each probe requests. We then calculate the mean pass rate and standard deviation across all the models, as well as the Shapiro-Wilk p-value to gauge how well the scores follow a normal distribution. This mean and standard deviation tell us how well the bag does at a particular probe & model.

When assessing a target, we calculate a "Z-score". Positive Z-scores mean better than average, negative Z-scores mean worse than average. For any probe/detector combination, roughly two-thirds of models get a Z-score between -1.0 and +1.0. The middle 10% of models score -0.125 to +0.125. This is labelled "competitive". A Z-score of +1.0 means the score was one standard deviation better than the mean score other models achieved for this probe & detector.

It's possible to get a great Z-score and a low absolute score. This means that while the target model performed badly, also other state-of-the-art models performed badly. Similarly, one can achieve a low Z-score and high absolute score; this can mean that while the model was not very weak in the given instance, other models are even less weak.

We artificially bound standard deviations at a non-zero minimum, to represent the inherent uncertainty in using an incomplete sample of all LLMs, and to make Z-score calculation possible even when the bag perfectly agrees.

## When is the bag updated?

The first benchmark is in summer 2024. We think something between twice-yearly and quarterly updates provides a good trade off between using recent models, and keeping results relevant long enough to be comparable.

## Spring 2025

### Bag contents

| 10^n category | 2^n category |   provider  |              model name              | params (B) |
|:-------------:|:------------:|:-----------:|:------------------------------------:|:----------:|
|       1       |       6      | abacusai    | dracarys-llama-3.1-70b-instruct      |     70     |
|       1       |       5      | ai21labs    | jamba-1.5-mini-instruct              |     52     |
|       2       |       9      | deepseek    | deepseek-r1-distill-qwen-7b          |     671    |
|       0       |       2      | deepseek    | deepseek-r1                          |     7.62   |
|       1       |       4      | google      | gemma-3-1b-it                        |     27     |
|       0       |       0      | google      | gemma-3-27b-it                       |     1      |
|       0       |       3      | ibm         | granite-3.0-3b-a800m-instruct        |     8      |
|       0       |       1      | ibm         | granite-3.0-8b-instruct              |     3      |
|       1       |       6      | meta        | llama-3.1-405b-instruct              |     70     |
|       2       |       8      | meta        | llama-3.3-70b-instruct               |     405    |
|       2       |       7      | meta        | llama-4-maverick-17b-128e-instruct   |     109    |
|       0       |       1      | microsoft   | phi-3.5-moe-instruct                 |     3.8    |
|       1       |       5      | microsoft   | phi-4-mini-instruct                  |     60.8   |
|       1       |       4      | mistralai   | mistral-small-24b-instruct           |     24     |
|       2       |       7      | mistralai   | mixtral-8x22b-instruct-v0.1          |     141    |
|       1       |       5      | nvidia      | llama-3.3-nemotron-super-49b-v1      |     49     |
|       0       |       3      | nvidia      | mistral-nemo-minitron-8b-8k-instruct |     8      |
|       2       |       7      | openai      | gpt-4o                               |     200    |
|       2       |       6      | qwen        | qwen2.5-7b-instruct                  |     122    |
|       0       |       2      | qwen        | qwen2.5-coder-32b-instruct           |     7      |
|       1       |       5      | qwen        | qwq-32b                              |     32     |
|       1       |       5      | writer      | palmyra-creative-122b                |     32     |
|       0       |       2      | zyphra      | zamba2-7b-instruct                   |     7      |

### Bag config

```
system:
  parallel_attempts: 32
  lite: false

run:
  generations: 3

plugins:
  probe_spec: ansiescape,atkgen.Tox,av_spam_scanning,continuation,dan.Ablation_Dan_11_0,dan.AutoDANCached,dan.DanInTheWild,divergence,encoding.InjectAscii85,encoding.InjectBase16,encoding.InjectBase2048,encoding.InjectBase32,encoding.InjectBase64,encoding.InjectBraille,encoding.InjectEcoji,encoding.InjectHex,encoding.InjectMorse,encoding.InjectNato,encoding.InjectROT13,encoding.InjectUU,encoding.InjectZalgo,exploitation.JinjaTemplatePythonInjection,exploitation.SQLInjectionEcho,exploitation.SQLInjectionSystem,goodside,grandma,latentinjection,leakreplay,lmrc,malwaregen,misleading,packagehallucination,phrasing,realtoxicityprompts,snowball,suffix,tap,topic.WordnetControversial,xss
  extended_detectors: false
  probes:
    encoding:
      payloads:
        - default
        - xss
        - slur_terms
  detectors:
    misleading:
      MustContradictNLI:
        hf_args:
          device: cuda
      MustRefuteClaimModel:
        hf_args:
          device: cuda
```

## Summer 2024

### Bag contents

| 10^n category |  provider  |               model name              | params (B) |
|:-------------:|:-----------|:--------------------------------------|-----------:|
|       1       | 01-ai      | yi-large                              |         34 |
|       2       | databricks | dbrx-instruct                         |        132 |
|       0       | google     | gemma-2-27b-it                        |         27 |
|       0       | google     | gemma-2b                              |          2 |
|       0       | mediatek   | breeze-7b-instruct                    |          7 |
|       0       | meta       | llama-3.1-8b-instruct                 |          8 |
|       1       | meta       | llama3-70b                            |         70 |
|       0       | microsoft  | phi-3-mini-128k-instruct              |        3.8 |
|       1       | microsoft  | phi-3-medium-4k-instruct              |         14 |
|       1       | mistral    | mistral-nemo-12b-instruct             |         12 |
|       2       | mistral    | mixtral-8x22b-instruct-v0.1           |        141 |
|       2       | nvidia     | nemotron-4-340b-instruct              |        340 |
|       1       | upstage    | solar-10.7b-instruct                  |       10.7 |

### Bag config

```
---
system:
  parallel_attempts: 32
  lite: false

run:
  generations: 3

plugins:
  probe_spec: atkgen.Tox,continuation,dan.DanInTheWildMini,dan.Ablation_Dan_11_0,encoding.InjectAscii85,encoding.InjectBase16,encoding.InjectBase2048,encoding.InjectBase32,encoding.InjectBase64,encoding.InjectBraille,encoding.InjectEcoji,encoding.InjectHex,encoding.InjectMorse,encoding.InjectNato,encoding.InjectROT13,encoding.InjectUU,goodside,grandma,knownbadsignatures,leakreplay,lmrc,malwaregen,misleading,packagehallucination,realtoxicityprompts,replay,snowball,suffix,tap,xss
  extended_detectors: false
  probes:
    encoding:
      payloads:
        - default,xss,slur_terms
  detectors:
    misleading:
      MustContradictNLI:
        hf_args:
          device: cuda
      MustRefuteClaimModel:
        hf_args:
          device: cuda
```

