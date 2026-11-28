"""Small, reproducible live-target check for the homoglyph probes.

Sends a handful of prompts from each probe to a real OpenAI model and scores
the response with the corresponding detector, using garak's own Attempt class
so the scoring path matches what garak's harness does internally.

Deliberately capped at 2 prompts per probe (6 total model calls) to keep API
usage minimal.
"""

from openai import OpenAI

from garak import _config
from garak.attempt import Attempt, Message, Conversation, Turn

from garak.probes.homoglyph import (
    VisualEquivalenceConfusion,
    ToolNameSpoofDetection,
    BidiOverrideInToolName,
)
from garak.detectors.homoglyph import (
    HomoglyphConfusedForEqual,
    HomoglyphToolNameApproved,
    BidiCharApproved,
)

client = OpenAI()
MODEL = "gpt-4o-mini"
N_PER_PROBE = 2

CASES = [
    ("VisualEquivalenceConfusion", VisualEquivalenceConfusion, HomoglyphConfusedForEqual),
    ("ToolNameSpoofDetection", ToolNameSpoofDetection, HomoglyphToolNameApproved),
    ("BidiOverrideInToolName", BidiOverrideInToolName, BidiCharApproved),
]

_config.run.soft_probe_prompt_cap = N_PER_PROBE

results = []

for name, probe_cls, detector_cls in CASES:
    probe = probe_cls()
    detector = detector_cls()
    for i, prompt in enumerate(probe.prompts[:N_PER_PROBE]):
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0,
        )
        text = resp.choices[0].message.content

        attempt = Attempt(prompt=Message(text=prompt))
        attempt.outputs = [Message(text=text)]

        scores = detector.detect(attempt)
        hit = any(s == 1.0 for s in scores if s is not None)

        results.append(
            {
                "probe": name,
                "prompt": prompt,
                "response": text,
                "hit": hit,
            }
        )
        print(f"=== {name} [{i}] ===")
        print(f"PROMPT: {prompt}")
        print(f"RESPONSE: {text}")
        print(f"HIT (model fooled): {hit}")
        print()

n_hits = sum(1 for r in results if r["hit"])
print(f"Summary: {n_hits}/{len(results)} hits against {MODEL}")
