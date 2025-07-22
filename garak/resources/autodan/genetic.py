# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import gc
import numpy as np
import torch
import random
import openai
import re
from nltk.corpus import stopwords, wordnet
from collections import defaultdict, OrderedDict
import sys
import time
from logging import getLogger
from typing import Tuple

from garak.resources.api import nltk
from garak.resources.autodan.model_utils import AutoDanPrefixManager, forward

logger = getLogger(__name__)


# TODO: Refactor into setup.py
try:
    _ = stopwords.words("english")
    _ = nltk.word_tokenize("This is a normal English sentence")
    _ = wordnet.synsets("word")
except LookupError as e:
    nltk.download("stopwords")
    nltk.download("punkt")
    nltk.download("wordnet")


# TODO: Could probably clean up the inputs here by using imports.
def autodan_ga(
    control_prefixes: list,
    score_list: list,
    num_elites: int,
    batch_size: int,
    crossover_rate=0.5,
    num_points=5,
    mutation=0.01,
    if_softmax=True,
    mutation_generator=None,
) -> list:
    """Genetic algorithm for creating AutoDAN samples.

    Args:
        control_prefixes (list): list of control prefixes
        score_list (list): list of scores for inputs
        num_elites (int): Number of "elite" (best scoring) samples to pass to next round
        batch_size (int): Number of samples to pass to the next round
        crossover_rate (float): Rate to perform crossover operation on parents
        num_points (int): Number of points to perform crossover
        mutation (float): Rate to perform mutation on offspring
        if_softmax (bool): Whether to use softmax weighting for roulette selection
        mutation_generator : Generator to use for mutation. Defaults to None.

    Returns:
        List of length `batch_size` consisting of `num_elites` elite parents and crossover/mutated offspring
    """
    score_list = [-x for x in score_list]
    # Step 1: Sort the score_list and get corresponding control_prefixes
    sorted_indices = sorted(
        range(len(score_list)), key=lambda k: score_list[k], reverse=True
    )
    sorted_control_prefixes = [control_prefixes[i] for i in sorted_indices]

    # Step 2: Select the elites
    elites = sorted_control_prefixes[:num_elites]

    # Step 3: Use roulette wheel selection for the remaining positions
    parents_list = roulette_wheel_selection(
        control_prefixes, score_list, batch_size - num_elites, if_softmax
    )

    # Step 4: Apply crossover and mutation to the selected parents
    mutated_offspring = apply_crossover_and_mutation(
        parents_list,
        crossover_probability=crossover_rate,
        num_points=num_points,
        mutation_rate=mutation,
        mutation_generator=mutation_generator,
    )
    # Combine elites with the mutated offspring
    next_generation = elites + mutated_offspring

    assert (
        len(next_generation) == batch_size
    ), f"Generated offspring did not match batch size. Expected {batch_size}. Got {len(next_generation)}"
    return next_generation


def autodan_hga(
    word_dict,
    control_prefixes,
    score_list,
    num_elites,
    batch_size,
    crossover_rate=0.5,
    mutation_rate=0.01,
    mutation_generator=None,
) -> Tuple[list, dict]:
    """Hierarchical genetic algorithm for AutoDAN sample generation

    Args:
        word_dict (dict): Dictionary containing words and their word-level scores
        control_prefixes (list): List of prefix words
        score_list (list): List of scores for prefixes
        num_elites (int): Number of elite parents to pass directly to next iteration
        batch_size (int): Total size of batch to pass to next iteration
        crossover_rate (float): Rate to perform crossover
        mutation_rate (float): Rate to perform mutation
        mutation_generator : Generator to use for mutation. Defaults to None.

    Returns:
        Tuple of next generation parents and word dictionary.
    """
    score_list = [-x for x in score_list]
    # Step 1: Sort the score_list and get corresponding control_suffixes
    sorted_indices = sorted(
        range(len(score_list)), key=lambda k: score_list[k], reverse=True
    )
    sorted_control_suffixes = [control_prefixes[i] for i in sorted_indices]

    # Step 2: Select the elites
    elites = sorted_control_suffixes[:num_elites]
    parents_list = sorted_control_suffixes[num_elites:]

    # Step 3: Construct word list
    word_dict = construct_momentum_word_dict(word_dict, control_prefixes, score_list)

    # Step 4: Apply word replacement with roulette wheel selection
    offspring = apply_word_replacement(word_dict, parents_list, crossover_rate)
    offspring = apply_gpt_mutation(
        offspring, mutation_rate, mutation_generator=mutation_generator
    )

    # Combine elites with the mutated offspring
    next_generation = elites + offspring

    assert len(next_generation) == batch_size
    return next_generation, word_dict


def roulette_wheel_selection(
    data_list: list, score_list: list, num_selected: int, if_softmax=True
) -> list:
    """Roulette wheel selection for multipoint crossover policy

    Args:
        data_list (list): list of test inputs
        score_list (list): list of input scores
        num_selected (int): integer for how many inputs to select from
        if_softmax (bool): Whether to use softmax for selection probability. Defaults to True.

    Returns:
        A list of `num_selected` strings from `data_list`, weighted by score.
    """
    if if_softmax:
        selection_probs = np.exp(score_list - np.max(score_list))
        selection_probs = selection_probs / selection_probs.sum()
    else:
        total_score = sum(score_list)
        selection_probs = [score / total_score for score in score_list]

    selected_indices = np.random.choice(
        len(data_list), size=num_selected, p=selection_probs, replace=True
    )
    selected_data = [data_list[i] for i in selected_indices]
    return selected_data


def apply_crossover_and_mutation(
    selected_data: list,
    crossover_probability=0.5,
    num_points=3,
    mutation_rate=0.01,
    mutation_generator=None,
) -> list:
    """Perform crossover and mutation on selected parents.

    Args:
        selected_data (list): List of selected parents for crossover and mutation.
        crossover_probability (float): Probability of performing crossover operation on selected parents.
        num_points (int): Number of points to perform crossover.
        mutation_rate (float): How frequently to apply gpt mutation to offspring.
        mutation_generator : Generator to use for mutation. Defaults to None.

    Returns:
        A list of crossed over and mutated children
    """
    offspring = []

    for i in range(0, len(selected_data), 2):
        parent1 = selected_data[i]
        parent2 = (
            selected_data[i + 1] if (i + 1) < len(selected_data) else selected_data[0]
        )

        if random.random() < crossover_probability:
            child1, child2 = crossover(parent1, parent2, num_points)
            offspring.append(child1)
            offspring.append(child2)
        else:
            offspring.append(parent1)
            offspring.append(parent2)

    mutated_offspring = apply_gpt_mutation(
        offspring, mutation_rate, mutation_generator=mutation_generator
    )

    return mutated_offspring


def crossover(str1: str, str2: str, num_points: int) -> Tuple[str, str]:
    """Perform crossover on input strings

    Args:
        str1 (str): first string for crossover
        str2 (str): second string for crossover
        num_points (int): number of points to perform crossover

    Returns:
        Tuple of strings after `num_points` crossovers.
    """
    sentences1 = [s for s in re.split(r"(?<=[.!?])\s+", str1) if s]
    sentences2 = [s for s in re.split(r"(?<=[.!?])\s+", str2) if s]

    max_swaps = min(len(sentences1), len(sentences2)) - 1
    # Catch rare case where max_swaps is negative
    if not max_swaps >= 0:
        max_swaps = 0
    num_swaps = min(num_points, max_swaps)
    # Catch error in random.sample when num_swaps gets weird.
    try:
        swap_indices = sorted(random.sample(range(1, max_swaps), num_swaps))
    except ValueError:
        return str1, str2

    new_str1, new_str2 = [], []
    last_swap = 0
    for swap in swap_indices:
        if random.choice([True, False]):
            new_str1.extend(sentences1[last_swap:swap])
            new_str2.extend(sentences2[last_swap:swap])
        else:
            new_str1.extend(sentences2[last_swap:swap])
            new_str2.extend(sentences1[last_swap:swap])
        last_swap = swap

    if random.choice([True, False]):
        new_str1.extend(sentences1[last_swap:])
        new_str2.extend(sentences2[last_swap:])
    else:
        new_str1.extend(sentences2[last_swap:])
        new_str2.extend(sentences1[last_swap:])

    return " ".join(new_str1), " ".join(new_str2)


def gpt_mutate(mutation_generator, sentence: str) -> str:
    """Call OpenAI API to mutate input sentences

    Args:
        sentence (str): Sentence to be mutated

    Returns:
        Mutated string
    """
    system_msg = "You are a helpful and creative assistant who writes well."
    user_message = (
        f"Please revise the following sentence with no changes to its length and only output "
        f"the revised version, the sentences are: \n '{sentence}'."
    )
    revised_sentence = sentence
    received = False
    while not received:
        try:
            # TODO: Make the model configurable.
            response = mutation_generator.generate(
                prompt=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_message},
                ]
            )
            revised_sentence = response[0].replace("\n", "")
            received = True
        except Exception as e:
            logger.error(e)
            error = sys.exc_info()[0]
            if (
                error == openai.APIError or error == openai.OpenAIError
            ):  # something is wrong: e.g. prompt too long
                print(f"OpenAI threw an error: {error}")
                return None
            if error == AssertionError:
                print("Assert error:", sys.exc_info()[1])  # assert False
            else:
                print("API error:", error)
            time.sleep(1)
    if revised_sentence.startswith("'") or revised_sentence.startswith('"'):
        revised_sentence = revised_sentence[1:]
    if revised_sentence.endswith("'") or revised_sentence.endswith('"'):
        revised_sentence = revised_sentence[:-1]
    if revised_sentence.endswith("'.") or revised_sentence.endswith('".'):
        revised_sentence = revised_sentence[:-2]
    logger.info(f"Revised sentence: {revised_sentence}")
    return revised_sentence


def apply_gpt_mutation(
    offspring: list, mutation_rate=0.01, reference: list = None, mutation_generator=None
) -> list:
    # TODO: Allow for use of local models in lieu of OpenAI
    """Use OpenAI or reference corpus to apply mutation.

    Args:
        offspring (list): list of offspring to apply mutation to
        mutation_rate (float): How frequently to mutate offspring using GPT or reference corpus
        reference (list): List of pregenerated prompts
        mutation_generator : Generator to use for mutation. Defaults to None.

    Returns:
        List of mutated offspring
    """
    if mutation_generator:
        for i in range(len(offspring)):
            if random.random() < mutation_rate:
                offspring[i] = gpt_mutate(
                    mutation_generator=mutation_generator, sentence=offspring[i]
                )
    else:
        for i in range(len(offspring)):
            if random.random() < mutation_rate:
                if reference is not None:
                    offspring[i] = random.choice(reference[(len(offspring)) :])
                else:
                    offspring[i] = replace_with_synonyms(offspring[i])
    return offspring


def replace_with_synonyms(sentence: str, num=10) -> str:
    """Function to replace words in sentences with synonyms.

    Args:
        sentence (str): input sentence
        num (int): Number of words to replace.

    Returns:
        String of input sentence with synonym replacements.
    """
    model_names = {
        "llama2",
        "meta",
        "vicuna",
        "lmsys",
        "guanaco",
        "theblokeai",
        "wizardlm",
        "mpt-chat",
        "mosaicml",
        "mpt-instruct",
        "falcon",
        "tii",
        "chatgpt",
        "modelkeeper",
        "prompt",
    }
    stop_words = set(stopwords.words("english"))
    words = nltk.word_tokenize(sentence)
    uncommon_words = [
        word
        for word in words
        if word.lower() not in stop_words and word.lower() not in model_names
    ]
    selected_words = random.sample(uncommon_words, min(num, len(uncommon_words)))
    for word in selected_words:
        synonyms = wordnet.synsets(word)
        if synonyms and synonyms[0].lemmas():
            synonym = synonyms[0].lemmas()[0].name()
            sentence = sentence.replace(word, synonym, 1)
    return sentence


def construct_momentum_word_dict(
    word_dict: dict, control_suffixes: list, score_list: list, top_k=30
) -> dict:
    """Construct word-level score dictionary

    Args:
        word_dict (dict): Dictionary of words and scores
        control_suffixes (list): List of words
        score_list (list): List of scores
        top_k (int): How many words to include in the next word_dict

    Returns:
        Dictionary of top_k words, according to score.
    """
    model_names = {
        "llama2",
        "meta",
        "vicuna",
        "lmsys",
        "guanaco",
        "theblokeai",
        "wizardlm",
        "mpt-chat",
        "mosaicml",
        "mpt-instruct",
        "falcon",
        "tii",
        "chatgpt",
        "modelkeeper",
        "prompt",
    }
    stop_words = set(stopwords.words("english"))
    if len(control_suffixes) != len(score_list):
        raise ValueError("control_suffixs and score_list must have the same length.")

    word_scores = defaultdict(list)

    for suffix, score in zip(control_suffixes, score_list):
        words = set(
            [
                word
                for word in nltk.word_tokenize(suffix)
                if word.lower() not in stop_words and word.lower() not in model_names
            ]
        )
        for word in words:
            word_scores[word].append(score)

    for word, scores in word_scores.items():
        avg_score = sum(scores) / len(scores)
        if word in word_dict:
            word_dict[word] = (word_dict[word] + avg_score) / 2
        else:
            word_dict[word] = avg_score

    sorted_word_dict = OrderedDict(
        sorted(word_dict.items(), key=lambda x: x[1], reverse=True)
    )
    topk_word_dict = dict(list(sorted_word_dict.items())[:top_k])

    return topk_word_dict


def get_synonyms(word: str) -> list:
    """Get synonyms for a given word

    Args:
        word (str): Word to find synonyms for

    Returns:
        List of synonyms for the input word.
    """
    synonyms = set()
    for syn in wordnet.synsets(word):
        for lemma in syn.lemmas():
            synonyms.add(lemma.name())
    return list(synonyms)


def word_roulette_wheel_selection(word: str, word_scores: dict) -> str:
    """Randomly chooses a word to replace the given word.

    Args:
        word (str): Input word
        word_scores (dict): Dictionary of words and scores

    Returns:
        A replacement word
    """
    total_score = sum(word_scores.values())
    if total_score == 0:
        return word
    pick = random.uniform(0, 1)
    current_prob = 0
    for synonym, score in word_scores.items():
        current_prob += score / total_score
        if current_prob > pick:
            return synonym


def replace_with_best_synonym(
    sentence: str, word_dict: dict, replace_rate: float
) -> str:
    """Given a sentence, replace words with their highest scoring synonym with probability `replace_rate`

    Args:
        sentence (str): Input sentence
        word_dict (dict): Dictionary of words and their scores
        replace_rate (float): Probability of performing replacement

    Returns:
        Sentence with words replaced
    """
    stop_words = set(stopwords.words("english"))
    model_names = {
        "llama2",
        "meta",
        "vicuna",
        "lmsys",
        "guanaco",
        "theblokeai",
        "wizardlm",
        "mpt-chat",
        "mosaicml",
        "mpt-instruct",
        "falcon",
        "tii",
        "chatgpt",
        "modelkeeper",
        "prompt",
    }
    words = nltk.word_tokenize(sentence)
    for i, word in enumerate(words):
        if word.lower() not in stop_words and word.lower() not in model_names:
            if random.random() < replace_rate:
                synonyms = get_synonyms(word)
                word_scores = {syn: word_dict.get(syn, 0) for syn in synonyms}
                best_synonym = word_roulette_wheel_selection(word, word_scores)
                if best_synonym:
                    words[i] = best_synonym
    return join_words_with_punctuation(words)


def apply_word_replacement(
    word_dict: dict, parents_list: list, replacement_rate=0.5
) -> list:
    """Run synonym replacement over all items in `parents_list`

    Args:
        word_dict (dict): Dictionary of words and their scores
        parents_list (list): List of parent strings
        replacement_rate (float): Probability of performing replacement

    Returns:
        List of parents with replacement.
    """
    return [
        replace_with_best_synonym(sentence, word_dict, replacement_rate)
        for sentence in parents_list
    ]


def join_words_with_punctuation(words: list) -> str:
    """Helper function to put sentences back together with punctuation

    Args:
        words (list): list of words -- a split sentence

    Returns:
        Sentence including punctuation
    """
    sentence = words[0]
    for word in words[1:]:
        if word in [",", ".", "!", "?", ":", ";", ")", "]", "}", "(", "'"]:
            sentence += word
        else:
            sentence += " " + word
    return sentence


def get_score_autodan(
    generator,
    conv_template,
    instruction,
    target,
    test_controls=None,
    crit=None,
    low_memory=False,
):
    """Get AutoDAN score for the instruction

    Args:
        generator (garak.generators.huggingface.Model): Generator for model
        conv_template (Conversation): Conversation template for the model
        instruction (str): Instruction to be given to the model
        target (str): Target output
        test_controls (list): List of test jailbreak strings
        crit (torch.nn.Loss): Loss function for the generator

    Returns:
        Torch tensor of losses
    """
    # Convert all test_controls to token ids and find the max length
    losses = []
    input_ids_list = []
    target_slices = []
    device = generator.device
    for item in test_controls:
        prefix_manager = AutoDanPrefixManager(
            generator=generator,
            conv_template=conv_template,
            instruction=instruction,
            target=target,
            adv_string=item,
        )
        input_ids = prefix_manager.get_input_ids(adv_string=item).to(device)
        if not low_memory:
            input_ids_list.append(input_ids)
            target_slices.append(prefix_manager._target_slice)

            # Pad all token ids to the max length
            pad_tok = 0
            for ids in input_ids_list:
                while pad_tok in ids:
                    pad_tok += 1

            # Find the maximum length of input_ids in the list
            max_input_length = max([ids.size(0) for ids in input_ids_list])

            # Pad each input_ids tensor to the maximum length
            padded_input_ids_list = []
            for ids in input_ids_list:
                pad_length = max_input_length - ids.size(0)
                padded_ids = torch.cat(
                    [ids, torch.full((pad_length,), pad_tok, device=device)], dim=0
                )
                padded_input_ids_list.append(padded_ids)

            # Stack the padded input_ids tensors
            input_ids = torch.stack(padded_input_ids_list, dim=0)

            attn_mask = (input_ids != pad_tok).type(input_ids.dtype)

        else:
            target_slices = prefix_manager._target_slice

    # Forward pass and compute loss
    logits = forward(
        generator=generator,
        input_ids=input_ids,
        attention_mask=attn_mask,
        batch_size=len(test_controls),
    )

    for idx, target_slice in enumerate(target_slices):
        loss_slice = slice(target_slice.start - 1, target_slice.stop - 1)
        logits_slice = logits[idx, loss_slice, :].unsqueeze(0).transpose(1, 2)
        targets = input_ids[idx, loss_slice].unsqueeze(0)
        loss = crit(logits_slice, targets)
        losses.append(loss)

    del input_ids_list, target_slices, input_ids, attn_mask
    gc.collect()
    return torch.stack(losses)
