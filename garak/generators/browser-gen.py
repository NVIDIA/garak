import asyncio
import json
import logging
from typing import List, Union

from pydantic import BaseModel

from garak import _config
from garak.generators import Generator

from browser_use import Agent
from browser_use.llm import ChatGoogle, ChatOpenAI
from playwright.async_api import async_playwright


class Response(BaseModel):
    """Model for a single agent response item."""

    response: str


class Responses(BaseModel):
    """Model for a list of agent response items."""

    responses: List[Response]


class BrowserUseGenerator(Generator):
    """Generator that uses browser_use agents to drive a web UI in parallel tabs.

    Runs multiple browser tabs within a single persistent profile and extracts
    text responses. Returns a list of strings compatible with Garak attempts.
    """

    # Disable cross-process parallelization since the shared browser profile
    # is not safe to use across multiple processes simultaneously.
    parallel_capable = False

    supports_multiple_generations = True
    generator_family_name = "BrowserUse"

    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        # Model and provider for the agent's internal LLM planner
        "name": "gpt-4o-mini",  # OpenAI model id, or Google model if llm_provider="google"
        "llm_provider": "openai",  # one of: "openai", "google"
        # BrowserUse settings
        "profile_dir": "./.config/browseruse/profiles/garak_session",
        "initial_actions": [
            {"go_to_url": {"url": "https://gemini.google.com/app?hl=en-AU", "new_tab": True}}
        ],
        # Concurrency and limits
        "parallel_requests": 4,  # cap concurrent tabs per prompt
        # Task template for the agent. {prompt} is substituted.
        "task_template": (
            "1. Enter the text: \"{prompt}\"\n"
            "2. Wait until the full response is visible\n"
            "3. Store the response\n"
            "4. End task\n"
        ),
    }

    def __init__(self, name: str = "", config_root=_config):
        # Load configuration prior to base init so fullname can be set
        self.name = name or self.DEFAULT_PARAMS["name"]
        self.llm_provider = "openai"
        self.profile_dir = None
        self.task_template = None
        self.initial_actions = None
        self.llm = None

        self._load_config(config_root)
        self.fullname = f"{self.generator_family_name} {self.name}"

        super().__init__(self.name, config_root=config_root)

    # Avoid pickling heavy runtime attributes if attempts are parallelized higher up
    def __getstate__(self):
        state = dict(self.__dict__)
        state["llm"] = None
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.llm = None

    def _ensure_runtime(self) -> None:
        """Lazily create LLM client and persistent browser profile."""
        if self.llm is None:
            if str(self.llm_provider).lower() == "google":
                self.llm = ChatGoogle(model=self.name)
            else:
                self.llm = ChatOpenAI(model=self.name)
        # Browser context is created per-call in _call_model using Playwright

    @staticmethod
    def _stringify_prompt(prompt: Union[str, List[dict]]) -> str:
        """Convert chat-style prompts into a single string for UI entry."""
        if isinstance(prompt, str):
            return prompt
        if isinstance(prompt, list):
            # Join user messages; fallback to concatenating all contents
            try:
                user_parts = [m.get("content", "") for m in prompt if m.get("role") == "user"]
                if not user_parts:
                    user_parts = [m.get("content", "") for m in prompt]
                return "\n".join([p for p in user_parts if isinstance(p, str)])
            except Exception:
                return json.dumps(prompt)
        return str(prompt)

    @staticmethod
    def _extract_text(result: str) -> List[str]:
        """Extract text outputs from the agent's final_result JSON or raw text.

        Tries `Responses` (list), then `Response` (single), else returns raw text.
        """
        if not result:
            return ["[ERROR] No result captured"]
        # Try structured formats first
        try:
            parsed = Responses.model_validate_json(result)
            return [r.response for r in parsed.responses]
        except Exception:
            pass
        try:
            single = Response.model_validate_json(result)
            return [single.response]
        except Exception:
            pass
        # Fallback raw
        return [result]

    async def _run_one_agent(self, task_text: str, page, initial_actions: List[dict]) -> List[str]:
        agent = Agent(task=task_text, llm=self.llm, page=page, initial_actions=initial_actions)
        history = await agent.run()
        return self._extract_text(history.final_result())

    def _build_task(self, prompt_text: str) -> str:
        try:
            return self.task_template.format(prompt=prompt_text)
        except Exception:
            # Very defensive: ensure we never raise due to bad template
            return (
                f"1. Enter the text: \"{prompt_text}\"\n"
                "2. Wait until the full response is visible\n"
                "3. Store the response\n"
                "4. End task\n"
            )

    def _call_model(
        self, prompt: Union[str, List[dict]], generations_this_call: int = 1
    ) -> List[Union[str, None]]:
        """Run N agents in parallel tabs and return N text outputs.

        Returns a list of strings of length `generations_this_call`.
        """
        # Prepare runtime resources each call to be resilient to pickling
        self._ensure_runtime()

        # Convert prompt into a UI-friendly string
        prompt_text = self._stringify_prompt(prompt)
        task_text = self._build_task(prompt_text)

        async def _runner():
            # Concurrency cap respecting configured parallel_requests
            limit = max(1, int(self.parallel_requests or 1))
            semaphore = asyncio.Semaphore(limit)

            async with async_playwright() as playwright:
                context = await playwright.chromium.launch_persistent_context(
                    user_data_dir=self.profile_dir,
                    headless=False,
                )

                async def _bounded_run():
                    async with semaphore:
                        page = await context.new_page()
                        try:
                            return await self._run_one_agent(
                                task_text, page, self.initial_actions or []
                            )
                        finally:
                            try:
                                await page.close()
                            except Exception:
                                pass

                # Launch N agents (new tabs in the same browser context)
                tasks = [_bounded_run() for _ in range(max(1, generations_this_call))]
                completed = await asyncio.gather(*tasks, return_exceptions=True)

                try:
                    await context.close()
                except Exception:
                    pass

            # Flatten each agent's list into one string per agent
            outputs: List[Union[str, None]] = []
            for item in completed:
                if isinstance(item, Exception):
                    logging.error("BrowserUse agent run failed: %s", repr(item))
                    outputs.append(None)
                else:
                    # prefer joining multi-part agent outputs to a single string
                    try:
                        outputs.append("\n".join(item))
                    except Exception:
                        outputs.append(None)
            return outputs

        # Run the async part with a clean event loop
        try:
            return asyncio.run(_runner())
        except RuntimeError:
            # Likely already inside an event loop; run in a new thread with its own loop
            from concurrent.futures import ThreadPoolExecutor

            def _run_in_thread():
                return asyncio.run(_runner())

            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_run_in_thread)
                return future.result()
        except Exception as exc:
            logging.exception(exc)
            return [None] * max(1, generations_this_call)

    def clear_history(self):
        # Best-effort cleanup between calls; keep profile directory for persistence
        self.llm = None


DEFAULT_CLASS = "BrowserUseGenerator"