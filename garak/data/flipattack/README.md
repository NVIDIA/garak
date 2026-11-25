# FlipAttack

The prompt templates in this folder are taken from the reference implementation of
FlipAttack, [`src/flip_attack.py`](https://github.com/yueliu1999/FlipAttack/blob/c53880b4a6e8ab47686849838b3d2e11bc80a6b9/src/flip_attack.py)
in the [FlipAttack repository](https://github.com/yueliu1999/FlipAttack). They are
available under the MIT License included here as `LICENSE`.

* `system_vanilla.txt`: system prompt for the vanilla and chain-of-thought variants
* `system_langgpt.txt`: LangGPT-structured system prompt
* `langgpt_steps.txt`: the task steps appended to the user turn by the LangGPT variants

They are used by the `flipattack` probes. If using them, please consider citing
[the FlipAttack paper](https://arxiv.org/abs/2410.02832):

```
@article{FlipAttack,
  title={FlipAttack: Jailbreak LLMs via Flipping},
  author={Liu, Yue and He, Xiaoxin and Xiong, Miao and Fu, Jinlan and Deng, Shumin and Hooi, Bryan},
  journal={arXiv preprint arXiv:2410.02832},
  year={2024}
}
```
