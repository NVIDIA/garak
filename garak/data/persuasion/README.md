# Persuasion taxonomy

This folder includes a copy of `persuasion_taxonomy.jsonl` from the
[persuasive_jailbreaker](https://github.com/CHATS-lab/persuasive_jailbreaker) repository,
which accompanies the paper *"How Johnny Can Persuade LLMs to Jailbreak Them: Rethinking
Persuasion to Challenge AI Safety by Humanizing LLMs"* (Zeng et al., 2024).

The file lists 40 persuasion techniques, each with a definition and a benign example. It is
used by `garak.probes.persuasion` to rewrite base requests into Persuasive Adversarial
Prompts (PAPs) at run time.

Only the openly-released persuasion taxonomy is vendored here. The authors deliberately
gate the full harmful PAP dataset behind a signed release form; garak does **not** ship or
download that data.

The upstream repository is distributed under the Apache License 2.0. If you use this data or
the `persuasion` probe, please consider citing the paper:

```
@misc{zeng2024johnny,
  title={How Johnny Can Persuade LLMs to Jailbreak Them: Rethinking Persuasion to Challenge AI Safety by Humanizing LLMs},
  author={Yi Zeng and Hongpeng Lin and Jingwen Zhang and Diyi Yang and Ruoxi Jia and Weiyan Shi},
  year={2024},
  eprint={2401.06373},
  archivePrefix={arXiv},
  primaryClass={cs.CL}
}
```
