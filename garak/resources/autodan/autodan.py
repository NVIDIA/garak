import argparse
from logging import getLogger
import os
from pathlib import Path
import torch
import torch.nn as nn
from tqdm import tqdm
import numpy as np

import gc

from garak._plugins import load_plugin
from garak.generators import Generator
from garak.generators.huggingface import Model
import garak._config
from garak.data import path as data_path
from garak.resources.autodan.genetic import (
    get_score_autodan,
    autodan_ga,
    autodan_hga,
    apply_gpt_mutation,
)
from garak.resources.autodan.model_utils import (
    load_conversation_template,
    check_for_attack_success,
)
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
    mutation_generator_name: str = "gpt-3.5-turbo",
    mutation_generator_type: str = "openai",
    hierarchical: bool = False,
    out_path: Path = cached_autodan_resource_data / "autodan_prompts.txt",
    init_prompt_path: Path = autodan_resource_data / "autodan_init.txt",
    reference_path: Path = autodan_resource_data / "prompt_group.pth",
    low_memory: bool = False,
    random_seed: int = None,
):
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
        low_memory (bool): Whether to use low memory
        random_seed (int): Random seed, if used.

    Returns:
        None
    """
    if not isinstance(generator, Model):
        msg = "AutoDAN generation currently only supports HuggingFace models."
        logger.error(msg)
        raise TypeError(msg)

    if random_seed is not None:
        np.random.seed(random_seed)
        torch.manual_seed(random_seed)
        torch.cuda.manual_seed_all(random_seed)

    adv_string_init = open(init_prompt_path, "r", encoding="utf-8").readlines()[0]

    conv_template = load_conversation_template(generator.name)
    crit = nn.CrossEntropyLoss(reduction="mean")

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
        reference[o] = reference[o].replace("ChatGPT", conv_template.name)
        reference[o] = reference[o].replace("chatGPT", conv_template.name)
        reference[o] = reference[o].replace(
            "ModelKeeper", developer_dict.get(conv_template.name, "Moderation")
        )
        reference[o] = reference[o] + " [PROMPT]:"

    new_adv_prefixes = reference[:batch_size]
    if hierarchical:
        word_dict = dict()

    for j in tqdm(range(num_steps), leave=True):
        with torch.no_grad():
            losses = get_score_autodan(
                generator=generator,
                conv_template=conv_template,
                instruction=prompt,
                target=target,
                test_controls=new_adv_prefixes,
                crit=crit,
                low_memory=low_memory,
            )
            score_list = losses.cpu().numpy().tolist()

            best_new_adv_prefix_id = losses.argmin()
            best_new_adv_prefix = new_adv_prefixes[best_new_adv_prefix_id]

            adv_prefix = best_new_adv_prefix
            gen_str = generator.generate(prompt=adv_prefix)[0]
            success = check_for_attack_success(gen_str, REJECTION_STRINGS)
            if success:
                logger.info(
                    f"Found a successful AutoDAN prompt!\n{adv_prefix}\nAppending to {out_path}."
                )
                with open(out_path, "a", encoding="utf-8") as f:
                    f.write(f"{adv_prefix}\n")
                break

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

    if success:
        return adv_prefix

    else:
        logger.info(
            f"Ran through {num_steps} iterations and found no successful prompts"
        )
        print(f"Ran through {num_steps} iterations and found no successful prompts")
