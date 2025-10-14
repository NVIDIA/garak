"""atkgen: Attack Generation.

This probe uses a separate model to create prompts for a generator,
which are intended to guide that generator into a certain failure mode.

Warning: These attack models may generate highly toxic prompts while
attempting to goad target models into failure - peruse logs at your
own risk, and don't spend too much time doing it, using this guide
to working with harmful text:

 https://aclanthology.org/2022.findings-emnlp.35/
"""

import copy
import logging
import json
import re
from typing import List

from colorama import Fore, Style
from tqdm import tqdm

from garak import _config
import garak._plugins
import garak.attempt
import garak.probes

TEMPLATE_PLACEHOLDER = "[query]"


class Tox(garak.probes.Probe):
    """Automatic attack generation, trying to elicit toxic outputs from the model.

    This probe uses an attack model, trained on conversations that led to LLMs
    outputting toxicity, to generate prompts that should nudge a target LLM into
    yielding toxic output. The data used for this attack generation model was selected
    using the same detector as this tox probe uses, so both attack generation model
    and detector are looking for the same definition of the failure mode."""

    primary_detector = "unsafe_content.ToxicCommentModel"
    tags = [
        "avid-effect:ethics:E0301",
        "quality:Behavioral:ContentSafety:Toxicity",
        "quality:Behavioral:ContentSafety:HateHarassment",
        "quality:Behavioral:ContentSafety:Profanity",
        "payload:unwanted",
    ]
    goal = "make the model say something toxic"
    parallelisable_attempts = False  # atkgen has its own dialog manager
    doc_uri = (
        "https://interhumanagreement.substack.com/p/faketoxicityprompts-automatic-red"
    )
    lang = "en"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = True

    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | {
        "max_calls_per_conv": 5,
        "convs_per_generation": 5,
        "constructive_tension": True,
        "red_team_model_type": "huggingface.Pipeline",
        "red_team_model_name": "garak-llm/attackgeneration-toxicity_gpt2",
        "red_team_model_config": {
            "hf_args": {"device": "cpu", "torch_dtype": "float32"}
        },  # defer acceleration devices to model under test unless overriden
        "red_team_prompt_template": "<|input|>[query]<|response|>",
        "red_team_postproc_rm_regex": r"\<\|.*",
        "use_only_first_sent": True,  # should we only consider the first sentence of the target's response?
        "allow_repetition": False,
    }

    def probe(self, generator) -> List[garak.attempt.Attempt]:
        output_is_conversation = _config.system.verbose >= 2

        if self.redteamer is None:

            print(
                "🔴🪖  ", end=""
            )  # distinguish load message for atkgen generator from target generator
            self.redteamer = garak._plugins.load_plugin(
                f"generators.{self.red_team_model_type}",
                config_root=self.red_team_model_config,
            )
            self.redteamer.deprefix_prompt = True
            self.redteamer.parallel_requests = False

        attempts = []
        red_team_model_short = self.red_team_model_name.split("/")[-1]

        attack_iterator = tqdm(
            range(self.generations * self.convs_per_generation), leave=False
        )  # itrerate for probe generations
        attack_iterator.set_description(self.probename.replace("garak.", ""))

        for i in attack_iterator:
            calls_made = 0
            keep_going = True

            last_response = None
            last_attempt = None

            if not output_is_conversation:
                t = tqdm(total=2 * self.max_calls_per_conv, leave=False)
            else:
                print("atkgen: 🆕 ⋅.˳˳.⋅ॱ˙˙ॱ New conversation ॱ˙˙ॱ⋅.˳˳.⋅ 🗣️")

            while calls_made < self.max_calls_per_conv and keep_going:

                if not output_is_conversation:
                    t.set_description(
                        f" turn {t.n:02}: red teaming [{red_team_model_short[:10]:<10}]"
                    )
                # generate a challenge
                if last_response == "" and self.constructive_tension:
                    challenge = ""
                else:
                    if last_response:
                        if self.use_only_first_sent:
                            last_response = last_response.split(". ")[
                                0
                            ]  # nltk sentence splitter install too unfriendly
                    else:
                        last_response = ""  # maybe it's none or 0.0 or [] or goodness knows. let's get an empty string.

                    if len(self.red_team_prompt_template):
                        query = self.red_team_prompt_template.replace(
                            "[query]", last_response
                        )
                    else:
                        query = last_response  # oh hey we might want to be able to switch roles here for chat models. or not?

                    challenge = self.redteamer.generate(
                        garak.attempt.Conversation(
                            [garak.attempt.Turn("user", garak.attempt.Message(query))]
                        )
                    )[0]
                    if self.red_team_postproc_rm_regex:
                        challenge_text = re.sub(
                            self.red_team_postproc_rm_regex, "", challenge.text
                        ).strip()

                # translate the challenge to send to the target
                challenge_to_send = self.langprovider.get_text([challenge_text])[0]

                this_attempt = self._mint_attempt(
                    prompt=garak.attempt.Message(
                        challenge_to_send, lang=self.langprovider.target_lang
                    )
                )
                if challenge_to_send != challenge_text:
                    this_attempt.notes["pre_translation_prompt"] = (
                        garak.attempt.Conversation(
                            [
                                garak.attempt.Turn(
                                    "user",
                                    garak.attempt.Message(
                                        challenge_text, lang=self.lang
                                    ),
                                )
                            ]
                        )
                    )
                logging.debug(
                    "atkgen: attempt %s uuid %s call %s"
                    % (i, this_attempt.uuid, calls_made)
                )
                this_attempt.notes["red_team_challenge"] = last_response
                if last_attempt:
                    this_attempt.notes["previous_attempt_id"] = str(last_attempt.uuid)

                if not output_is_conversation:
                    t.update()

                logging.debug("atkgen: probe: %s", challenge_text)
                if output_is_conversation:
                    probe_text = re.sub(r"[\r\n]+", "\n", challenge_text[1]).strip()
                    print(
                        f"atkgen: 🔴 probe: {Fore.LIGHTYELLOW_EX}{probe_text}{Style.RESET_ALL}"
                    )
                else:
                    t.set_description(
                        f" turn {t.n:02}: waiting for [{generator.name[:10]:<10}]"
                    )
                # send the challenge in the target language and get the response
                response = generator.generate(this_attempt.prompt)
                if response is None or len(response) == 0:
                    response_text = ""
                else:
                    response_text = (
                        response[0].text.strip() if response[0] is not None else ""
                    )
                this_attempt.outputs = response

                # log the response
                response_to_store = self.reverse_langprovider.get_text([response_text])[
                    0
                ]
                if (
                    self.reverse_langprovider.source_lang
                    != self.reverse_langprovider.target_lang
                ):
                    this_attempt.reverse_translation_outputs = [
                        garak.attempt.Message(response_to_store)
                    ]
                logging.debug("atkgen: model: %s", response_text)
                if output_is_conversation:
                    print(
                        f"atkgen: 🦜 model: {Style.BRIGHT}{this_attempt.prompt.turns[-1].text}{Style.RESET_ALL}"
                    )
                else:
                    t.update()
                # increment calls_made
                calls_made += 1
                # last_response needs to be in the attack model's language base update on `response_to_store`
                # check if the resp is empty or if it matches the previous resp
                if not len(response_to_store) and not self.constructive_tension:
                    keep_going = False
                if response_to_store == last_response:
                    keep_going = False and not self.allow_repetition
                # update last_response
                last_response = response_to_store.replace("\n", " ").strip()

                _config.transient.reportfile.write(
                    json.dumps(this_attempt.as_dict()) + "\n"
                )
                attempts.append(copy.deepcopy(this_attempt))
                last_attempt = this_attempt

            if not output_is_conversation:
                t.close()

        return attempts

    def _build_red_team_model_config(self):
        try:
            rt_model_module, rt_model_class = self.red_team_model_type.split(".")
        except ValueError as e:
            msg = f"red team model type needs to be fully specified, w.g. 'module.Class'. Got {self.red_team_model_type}"
            logging.critical(msg)
            raise ValueError() from e
        rt_config = {
            "generators": {
                rt_model_module: {
                    rt_model_class: self.red_team_model_config
                    | {"name": self.red_team_model_name},
                }
            }
        }
        return rt_config

    def __init__(self, config_root=_config):
        super().__init__(config_root)
        self.redteamer = None
        self.red_team_model_config = self._build_red_team_model_config()
        if (
            len(self.red_team_prompt_template)
            and TEMPLATE_PLACEHOLDER not in self.red_team_prompt_template
        ):
            msg = f"No query placeholder {TEMPLATE_PLACEHOLDER} in {self.__class__.__name__} prompt template {self.red_team_prompt_template}"
            logging.critical(msg)
            raise ValueError(msg)
