"""Detectors that rely on the attempt notes to detect a probe hit / LLM failure."""

from typing import List

from garak.detectors.base import Detector
from garak.attempt import Attempt

class MatchSuccessBool(Detector):
    """Check if the `success` boolean is True in the attempt notes.
    Return 1.0 if True, 0.0 if False or not present."""

    lang_spec = "*"

    def detect(self, attempt: Attempt) -> List[float]:
        results = []
        for output in attempt.outputs:
            if output is None or output.text is None:
                results.append(None)
                continue

            # check if output has notes and success key and is a boolean
            if (hasattr(output, "notes") and 
                isinstance(output.notes, dict) and 
                "success" in output.notes and 
                isinstance(output.notes["success"], bool)):
                results.append(1.0 if output.notes["success"] else 0.0)
            else:
                # for outputs without proper success flag, return 0.0
                results.append(0.0)
        return results