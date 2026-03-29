"""**Misleading claims**

Pose targets with false claims and check if they successfully debunk/reject them.

This module homes probes that attempt to mislead the target.

Will a model refute false claims, or will it go along with false information
and perform tasks based on them? This checks for a subset of hallucination
types, where false information is present that the system is expected to
deny, refute, or contradict.
"""

from garak import _config
from garak.data import path as data_path
import garak.probes


class FalseAssertion(garak.probes.Probe):
    """Does the model reject [questions based on] false claims?

    Poses a number of false statements to the model and checks to see if the model
    refutes the statement, contradicts the statement, or issues a safety mitigation
    message."""

    lang = "en"
    doc_uri = "https://arxiv.org/abs/2304.13734"
    primary_detector = "misleading.MustRefuteClaimModel"
    extended_detectors = [
        "misleading.MustRefuteClaimKW",
        "mitigation.MitigationBypass",
        "misleading.MustContradictNLI",
    ]
    tags = [
        "avid-effect:performance:P0204",
        "owasp:llm09",
        "quality:Robustness:GenerativeMisinformation",
        "payload:hallucination",
    ]
    goal = "make the model expand on a false assertion"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = True

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)

        prefixes = ["", "Why is it that", "Explain why"]

        self.prompts = []

        for prefix in prefixes:
            with open(
                data_path / "truefalse_falseclaims_50.txt",
                "r",
                encoding="utf-8",
            ) as assertions:
                for false_assertion in assertions:
                    false_assertion = false_assertion.strip()
                    if not false_assertion:
                        continue
                    if not prefix:
                        self.prompts.append(false_assertion)
                    else:
                        if false_assertion.startswith("The"):
                            false_assertion = "t" + false_assertion[1:]
                        self.prompts.append(f"{prefix} {false_assertion}")


class FabricatedRegulatoryCitation(garak.probes.Probe):
    """Does the model expand on fabricated regulatory control numbers?

    Poses questions referencing nonexistent regulatory controls (e.g. NIST SP
    800-171 control 3.99.1, CMMC Level 5, DFARS 252.204-7099, HIPAA 164.999)
    and checks whether the model refutes the premise or fabricates an
    authoritative-sounding response. Targets the same failure mode as
    FalseAssertion (accepting and elaborating on false information), applied
    to compliance frameworks where hallucinated citations carry legal and audit
    risk."""

    lang = "en"
    doc_uri = "https://arxiv.org/abs/2304.13734"
    primary_detector = "misleading.MustRefuteClaimModel"
    extended_detectors = [
        "misleading.MustRefuteClaimKW",
        "mitigation.MitigationBypass",
    ]
    tags = [
        "avid-effect:performance:P0204",
        "owasp:llm09",
        "quality:Robustness:GenerativeMisinformation",
        "payload:hallucination",
    ]
    goal = "make the model expand on a fabricated regulatory citation"
    tier = garak.probes.Tier.COMPETE_WITH_SOTA
    active = False

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)

        self.prompts = []

        with open(
            data_path / "falseclaims_regulatory_25.txt",
            "r",
            encoding="utf-8",
        ) as claims:
            for claim in claims:
                claim = claim.strip()
                if not claim:
                    continue
                self.prompts.append(claim)
