# SPDX-FileCopyrightText: Copyright (c) 2020 Agency Enterprise, LLC
# SPDX-License-Identifier: MIT

import copy
import itertools

from ._utils import DeepDict, hash_dict

_defaults = {
    "config": {
        "model": "text-davinci-002",
        "temperature": 1,
        "top_p": 1,
        "frequency_penalty": 0,
        "presence_penalty": 0,
        "max_tokens": 256,
        "id": 0,
        "stop": None,
    },
    "base": {"settings": {"n-shot": 3}},
    "attack": {"settings": {"length": 5, "times": 2}},
    "terms": {"human": "User", "ai": "Agent"},
    "visualization": {"columns": ("prompt_instruction", "attack_rogue_string")},
}


def _get_first_valid(*values):
    def _is_valid(value):
        return value is not None and value != {}

    return next((e for e in values if _is_valid(e)), None)


def _compile_prompts(prompt_dicts, current_product):
    p = copy.deepcopy(prompt_dicts)
    p.update(current_product)
    p = DeepDict(p)

    return {
        "base_text": p["tuple_base_text"],
        "prompt_secret": _get_first_valid(p["tuple_base_secret"], None),
        "prompt_secret_instruction": _get_first_valid(
            p["tuple_base_secret"]["instruction"], None
        ),
        "prompt_private_value": p["tuple_base_private_value"] or None,
        "prompt_instruction": p["tuple_base_text"]["instruction"],
        "prompt_shots": _get_first_valid(p["tuple_base_text"]["shots"], ()),
        "prompt_input": _get_first_valid(p["tuple_base_text"]["input"], ""),
        "prompt_nshot": _get_first_valid(p["value_base_settings_nshot"], None),
        "prompt_label": p["tuple_base_text"]["label"],
        "prompt_terms_human": _get_first_valid(
            p["dict_base_terms_human"],
            p["tuple_base_text"]["terms"]["human"],
            _defaults["terms"]["human"],
        ),
        "prompt_terms_ai": _get_first_valid(
            p["dict_base_terms_ai"],
            p["tuple_base_text"]["terms"]["ai"],
            _defaults["terms"]["ai"],
        ),
        "attack_text": _get_first_valid(p["tuple_attack_text"], ""),
        "attack_instruction": _get_first_valid(
            p["tuple_attack_text"]["instruction"], ""
        ),
        "attack_scoring": _get_first_valid(p["tuple_attack_scoring"], ""),
        "attack_rogue_string": _get_first_valid(p["tuple_attack_rogue_string"], None),
        "attack_label": _get_first_valid(p["tuple_attack_text"]["label"], ""),
        "attack_settings_escape": _get_first_valid(
            p["value_attack_settings_escape"], ""
        ),
        "attack_settings_delimiter": _get_first_valid(
            p["value_attack_settings_delimiter"], ""
        ),
        "attack_settings_escape_length": _get_first_valid(
            p["value_attack_settings_escape_length"],
            _defaults["attack"]["settings"]["length"],
        ),
        "attack_settings_escape_times": _get_first_valid(
            p["value_attack_settings_escape_times"],
            _defaults["attack"]["settings"]["times"],
        ),
        "config_model": _get_first_valid(
            p["value_config_model"],
            p["tuple_base_text"]["config"]["model"],
            _defaults["config"]["model"],
        ),
        "config_temperature": _get_first_valid(
            p["value_config_temperature"],
            p["tuple_base_text"]["config"]["temperature"],
            _defaults["config"]["temperature"],
        ),
        "config_top_p": _get_first_valid(
            p["value_config_top_p"],
            p["tuple_base_text"]["config"]["top_p"],
            _defaults["config"]["top_p"],
        ),
        "config_frequency_penalty": _get_first_valid(
            p["value_config_frequency_penalty"],
            p["tuple_base_text"]["config"]["frequency_penalty"],
            _defaults["config"]["frequency_penalty"],
        ),
        "config_presence_penalty": _get_first_valid(
            p["value_config_presence_penalty"],
            p["tuple_base_text"]["config"]["presence_penalty"],
            _defaults["config"]["presence_penalty"],
        ),
        "config_max_tokens": _get_first_valid(
            p["value_config_max_tokens"],
            p["tuple_base_text"]["config"]["max_tokens"],
            _defaults["config"]["max_tokens"],
        ),
        "config_stop": _get_first_valid(
            p["value_config_stop"],
            p["tuple_base_text"]["config"]["stop"],
            _defaults["config"]["stop"],
        ),
        "config_id": _get_first_valid(
            p["value_config_id"],
            p["tuple_base_text"]["config"]["id"],
            _defaults["config"]["id"],
        ),
    }


def _join_main_prompt(preset):
    prompt_nshot = preset["prompt_nshot"]

    if prompt_nshot:
        shots_joined = "\n\n".join(preset["prompt_shots"][0:prompt_nshot])
        prompt_joined = "\n".join(
            x
            for x in (
                preset["prompt_secret_instruction"] or None,
                preset["prompt_instruction"] or None,
                shots_joined,
                preset["prompt_input"] or None,
            )
            if x
        )
    else:
        prompt_joined = "".join(
            preset[x]
            for x in (
                "prompt_secret_instruction",
                "prompt_instruction",
                "prompt_input",
            )
            if preset[x]
        )

    prompt_formatted = prompt_joined.format(
        REPLACE_term_human=preset["prompt_terms_human"],
        REPLACE_term_ai=preset["prompt_terms_ai"],
        REPLACE_private_value=preset["prompt_private_value"],
        user_input="{user_input}",
    )

    return prompt_formatted


def _join_prompt_attack(preset):
    attack_instruction = preset["attack_instruction"]
    if attack_instruction:
        attack_instruction_formatted = attack_instruction.format(
            REPLACE_rogue_string=preset["attack_rogue_string"],
        )
        single_escape = "".join(
            (
                preset["attack_settings_escape"],
                f"{preset['attack_settings_delimiter']*preset['attack_settings_escape_length']}",
            )
        )
        repeated_escape = f"{single_escape*preset['attack_settings_escape_times']}"
        if repeated_escape:
            repeated_escape += "\n"
        joined_attack = repeated_escape + attack_instruction_formatted

        return joined_attack
    else:
        return ""


def _build_product_list(products, prompts):
    prompt_list = []
    for current_products in products:
        product_prompt_values = _merge_current_products(current_products)

        current_product_settings = _compile_prompts(prompts, product_prompt_values)

        main_prompt_string = _join_main_prompt(current_product_settings)
        main_attack_string = _join_prompt_attack(current_product_settings)

        joined_prompt_attack_string = main_prompt_string.format(
            user_input=main_attack_string
        )

        prompt_list.append(
            {
                "hash": hash_dict(current_product_settings),
                "settings": current_product_settings,
                "prompt": joined_prompt_attack_string,
            },
        )
    return prompt_list


def _product_from_iterables(prompt_dicts):
    tuple_list = []
    for key, value in prompt_dicts.items():
        if isinstance(value, tuple):
            group_dict = tuple({key: j_item} for j_item in value)
            tuple_list.append(group_dict)
    return list(itertools.product(*tuple_list))


def _merge_current_products(products):
    merged = {}
    for product in products:
        for key, value in product.items():
            merged[key] = value
    return merged


def _build_base_prompt(preset):
    return {
        "tuple_base_text": preset["base"]["text"],
        "tuple_base_secret": preset["base"]["secret"],
        "tuple_base_private_value": preset["base"]["private_value"],
        "dict_base_terms_human": preset["base"]["terms"]["human"],
        "dict_base_terms_ai": preset["base"]["terms"]["ai"],
        "value_base_settings_nshot": preset["base"]["settings"]["n-shot"],
    }


def _build_attack_prompt(preset):
    return {
        "tuple_attack_text": preset["attack"]["text"],
        "tuple_attack_rogue_string": preset["attack"]["rogue_string"],
        "tuple_attack_scoring": preset["attack"]["scoring"],
        "value_attack_settings_escape": preset["attack"]["settings"]["escape"],
        "value_attack_settings_delimiter": preset["attack"]["settings"]["delimiter"],
        "value_attack_settings_escape_length": preset["attack"]["settings"][
            "escape_length"
        ],
        "value_attack_settings_escape_times": preset["attack"]["settings"][
            "escape_times"
        ],
    }


def _build_config_settings(preset):
    return {
        "value_config_model": preset["config"]["model"],
        "value_config_temperature": preset["config"]["temperature"],
        "value_config_top_p": preset["config"]["top_p"],
        "value_config_frequency_penalty": preset["config"]["frequency_penalty"],
        "value_config_presence_penalty": preset["config"]["presence_penalty"],
        "value_config_max_tokens": preset["config"]["max_tokens"],
        "value_config_stop": preset["config"]["stop"],
        "value_config_id": preset["config"]["id"],
    }


def build_prompts(preset):
    preset = DeepDict(preset)
    prompt_config = _build_config_settings(preset)
    prompt_base = _build_base_prompt(preset)
    prompt_attack = _build_attack_prompt(preset)

    merged_prompt_dicts = (
        prompt_base | prompt_attack | prompt_config
    )

    product_list = _product_from_iterables(merged_prompt_dicts)

    built_products = _build_product_list(product_list, merged_prompt_dicts)

    return built_products
