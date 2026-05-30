"""Always detectors

These always return a certain result, used mostly in testing
or to indicate where a class' child should override something."""

import random
from typing import List

from garak.attempt import Attempt
from garak.detectors.base import Detector


class Fail(Detector):
    """Always Fail (for testing & prototyping)"""

    lang_spec = "*"

    def detect(self, attempt: Attempt) -> List[float | None]:
        return [1.0] * len(attempt.outputs)


class Pass(Detector):
    """Always Pass (for testing & prototyping)"""

    lang_spec = "*"

    def detect(self, attempt: Attempt) -> List[float | None]:
        return [0.0] * len(attempt.outputs)


class Passthru(Detector):
    """Send existing attempt detection results; use first detector"""

    lang_spec = "*"

    DEFAULT_PARAMS = Detector.DEFAULT_PARAMS | {
        "skip": True,
    }

    def detect(self, attempt: Attempt) -> List[float | None]:
        assert (
            len(attempt.detector_results) > 0
        ), "Only use passthru on attempts that already have detector scores"
        detector_chosen = sorted(list(attempt.detector_results.keys()))[0]
        return attempt.detector_results[detector_chosen]


class Random(Detector):
    """Always return a random result (for testing & prototyping)"""

    lang_spec = "*"

    def detect(self, attempt: Attempt) -> List[float | None]:
        return [random.random() for _ in range(len(attempt.outputs))]
