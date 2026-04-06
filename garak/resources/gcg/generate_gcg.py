# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Union, Optional
from pathlib import Path
from logging import getLogger

CONTROL_INIT = "! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! !"

from garak.generators.huggingface import Pipeline, Model
from garak.resources.gcg.attack_manager import GCGAttack, get_goals_and_targets

import garak._config

logger = getLogger(__name__)

gcg_cache_data = garak._config.transient.cache_dir / "data" / "gcg"


def run_gcg(
    target_generator: Union[Pipeline, Model] = None,
    stop_success: bool = True,
    goal_str: Optional[str] = None,
    target_str: Optional[str] = None,
    train_data: Optional[str] = None,
    n_train: int = 50,
    outfile: Path = gcg_cache_data / "gcg.txt",
    control_init: str = CONTROL_INIT,
    n_steps: int = 500,
    batch_size: int = 128,
    topk: int = 256,
    anneal: bool = False,
    filter_cand: bool = True,
    system_prompt: Optional[str] = None,
):
    """Function to generate GCG attack strings

    Args:
        target_generator (Generator): Generator to target with GCG attack
        stop_success (bool): Whether to stop on a successful attack
        goal_str (str): Input to optimize
        target_str (str): Target output string
        train_data (str): Path to training data
        n_train (int): Number of training examples to use
        outfile (Path): Where to write successful prompts
        control_init (str): Initial adversarial suffix to modify
        n_steps (int): Number of training steps
        batch_size(int):  Training batch size
        topk (int): Model hyperparameter for top k
        anneal (bool): Whether to use annealing
        filter_cand (bool): Whether to filter candidates to ensure that tokenizer encodes/decodes to the same text
        system_prompt (str): Optional system prompt.

    Kwargs:
        test_data (str): Path to test data

    Returns:
        None
    """

    if goal_str is not None and target_str is not None:
        train_goals = [goal_str]
        train_targets = [target_str]
    else:
        train_goals, train_targets = get_goals_and_targets(
            train_data=train_data, n_train=n_train
        )

    attack = GCGAttack(
        goals=train_goals,
        targets=train_targets,
        generator=target_generator,
        system_prompt=system_prompt,
        control_init=control_init,
        outfile=outfile,
    )

    logger.info("Beginning GCG generation")
    adv_suffix = attack.run(
        n_steps=n_steps,
        batch_size=batch_size,
        topk=topk,
        anneal=anneal,
        stop_on_success=stop_success,
        filter_cand=filter_cand,
    )

    if adv_suffix:
        return adv_suffix
    else:
        return None
