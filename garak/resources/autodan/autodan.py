# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import argparse
from logging import getLogger
import os
from pathlib import Path
import torch
from tqdm import tqdm
import numpy as np
from typing import Optional

import gc

from garak._plugins import load_plugin
from garak.generators import Generator
from garak.generators.huggingface import Model, Pipeline
from garak.attempt import Conversation, Turn, Message
import garak._config
from garak.data import path as data_path
from garak.resources.autodan.genetic import (
    get_score_autodan,
    autodan_ga,
    autodan_hga,
    apply_gpt_mutation,
)
from garak.resources.autodan.model_utils import check_for_attack_success
from garak.resources.common import REJECTION_STRINGS

logger = getLogger(__name__)

autodan_resource_data = data_path / "autodan"
cached_autodan_resource_data = garak._config.transient.cache_dir / "data" / "autodan"
autodan_parser = argparse.ArgumentParser(description="AutoDAN config")
autodan_parser.add_argument(
    "--num_steps", type=int, default=100, help="Number of steps to run generation"
)
autodan_parser.add_argument("--batch_size", type=int, default=64, help="Batch size")
autodan_parser.add_argument(
    "--num_elites",
    type=float,
    default=20,
    help="Number of parents to pass unmutated to the next generation",
)
autodan_parser.add_argument(
    "--crossover_rate",
    type=float,
    default=0.5,
    help="Probability of performing crossover",
)
autodan_parser.add_argument(
    "--num_points", type=int, default=5, help="Number of points to perform crossover"
)
autodan_parser.add_argument(
    "--mutation", type=float, default=0.01, help="Probability of mutation"
)
autodan_parser.add_argument(
    "--init_prompt_path",
    type=str,
    default=autodan_resource_data / "autodan_init.txt",
    help="Path to initial prompt",
)
autodan_parser.add_argument(
    "--reference",
    type=str,
    default=autodan_resource_data / "prompt_group.pth",
    help="Path to refernces",
)
autodan_parser.add_argument(
    "--low_memory", action="store_true", help="Use low memory mode"
)

developer_dict = {"llama2": "Meta"}

allow_non_ascii = False


def autodan_generate(
    generator: Generator,
    prompt: str,
    target: str,
    num_steps: int = 100,
    batch_size: int = 8,
    num_elites: int = 2,
    crossover_rate: float = 0.5,
    num_points: int = 5,
    mutation_rate: float = 0.1,
    mutation_generator_name: str = "mistralai/mixtral-8x22b-instruct-v0.1",
    mutation_generator_type: str = "nim.NVOpenAIChat",
    hierarchical: bool = False,
    out_path: Path = cached_autodan_resource_data / "autodan_prompts.txt",
    init_prompt_path: Path = autodan_resource_data / "autodan_init.txt",
    reference_path: Path = autodan_resource_data / "prompt_group.pth",
    stop_on_success: bool = True,
    random_seed: int = None,
    system_prompt: Optional[str] = None,
) -> list[str]:
    """Execute base AutoDAN generation

    Args:
        generator (garak.generators.Generator): Loaded Garak generator
        prompt(str): Malicious instruction to model
        target (str): Output we wish the model to return
        num_steps (int): How many steps to optimize over
        batch_size (int): Batch size for model
        num_elites (int): How many elite strings to pass to the next iteration of the GA
        crossover_rate (float): Probability of performing crossover
        num_points (int): How many points in an input to perform crossover on
        mutation_rate (float): Probability of mutating a parent string
        mutation_generator_name (str): Name of model to use as the mutation generator
        mutation_generator_type (str): Type of model to use as the mutation generator
        hierarchical (bool): Whether ot use hierarchical GA
        out_path (Path): Path to write generated AutoDAN string
        init_prompt_path (Path): Path to initial prompts
        reference_path (Path): Path to reference prompt tensors
        stop_on_success (bool): Return on first success
        random_seed (int): Random seed, if used.
        system_prompt (str): Optional system prompt

    Returns:
        List of successful adversarial prefixes
    """
    if not type(generator) is Pipeline and not isinstance(generator, Model):
        raise TypeError(f"Expected Pipeline or Model but got {type(generator)}")

    if random_seed is not None:
        np.random.seed(random_seed)
        torch.manual_seed(random_seed)
        torch.cuda.manual_seed_all(random_seed)

    adv_string_init = open(init_prompt_path, "r", encoding="utf-8").readlines()[0]

    config_root = {
        "generators": {mutation_generator_type: {"name": mutation_generator_name}}
    }
    mutation_generator = load_plugin(
        "generators." + mutation_generator_type, config_root=config_root
    )

    # Feel like this could just be text instead of storing it as tensors.
    if os.path.exists(reference_path):
        reference = torch.load(reference_path, map_location="cpu")
    else:
        init_prompts = [adv_string_init] * batch_size * 2  # suggested
        reference = apply_gpt_mutation(init_prompts, mutation_rate=1)
        torch.save(reference, reference_path)

    # TODO: Have this support references other than ChatGPT.
    for o in range(len(reference)):
        reference[o] = reference[o].replace("ChatGPT", generator.name)
        reference[o] = reference[o].replace("chatGPT", generator.name)
        reference[o] = reference[o].replace(
            "ModelKeeper", developer_dict.get(generator.name, "Moderation")
        )
        reference[o] = reference[o] + " [PROMPT]:"

    new_adv_prefixes = reference[:batch_size]
    if hierarchical:
        word_dict = dict()

    successful_prefixes = list()

    for j in tqdm(range(num_steps), leave=False, position=0, colour="green"):
        with torch.no_grad():
            score_list = get_score_autodan(
                generator=generator,
                instruction=prompt,
                target=target,
                test_controls=new_adv_prefixes,
                system_prompt=system_prompt,
            )

            best_new_adv_prefix_id = np.argmin(score_list)
            best_new_adv_prefix = new_adv_prefixes[best_new_adv_prefix_id]

            adv_prefix = best_new_adv_prefix
            conv = Conversation(
                turns=[Turn(role="user", content=Message(text=adv_prefix))]
            )
            gen_output = generator.generate(prompt=conv)[0]
            success = False
            if gen_output and gen_output.text:
                success = check_for_attack_success(gen_output.text, REJECTION_STRINGS)
            if success:
                logger.info(
                    f"Found a successful AutoDAN prompt! Appending to {out_path}."
                )
                successful_prefixes.append(adv_prefix)
                outpathdir = Path(out_path).parent
                outpathdir.mkdir(parents=True, exist_ok=True)
                try:
                    with open(out_path, "a", encoding="utf-8") as f:
                        f.write(f"{adv_prefix}\n")
                except FileNotFoundError as e:
                    logger.error(f"Failed to open {out_path}: {e}")
                except PermissionError as e:
                    logger.error(f"Failed to open {out_path}: {e}")
                if stop_on_success:
                    break
                else:
                    continue

            if hierarchical:
                unfiltered_new_adv_prefixes, word_dict = autodan_hga(
                    word_dict=word_dict,
                    control_prefixes=new_adv_prefixes,
                    score_list=score_list,
                    num_elites=num_elites,
                    batch_size=batch_size,
                    crossover_rate=crossover_rate,
                    mutation_rate=mutation_rate,
                    mutation_generator=mutation_generator,
                )
            else:
                unfiltered_new_adv_prefixes = autodan_ga(
                    control_prefixes=new_adv_prefixes,
                    score_list=score_list,
                    num_elites=num_elites,
                    batch_size=batch_size,
                    crossover_rate=crossover_rate,
                    num_points=num_points,
                    mutation=mutation_rate,
                    mutation_generator=mutation_generator,
                )

            new_adv_prefixes = unfiltered_new_adv_prefixes
            generator.clear_history()
            gc.collect()
            torch.cuda.empty_cache()

    if successful_prefixes:
        return successful_prefixes

    else:
        logger.info(
            f"AutoDAN ran {num_steps} iterations and found no successful prompts"
        )
        print(
            f"🎺☹️ AutoDAN ran {num_steps} iterations and found no successful prompts"
        )
