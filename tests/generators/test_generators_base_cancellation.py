"""Regression tests for cancelling parallel generator requests."""

from multiprocessing import TimeoutError
from pathlib import Path
import subprocess
import sys
import textwrap
from unittest.mock import patch

import pytest

from garak.attempt import Conversation, Message, Turn
from garak.generators.base import Generator


@pytest.fixture
def parallel_generation():
    """Provide a generator and a pool without starting real workers."""
    generator = Generator(name="cancellation test")
    generator.parallel_requests = 2
    generator.max_workers = 2
    prompt = Conversation([Turn("user", Message("hello"))])
    with patch("multiprocessing.Pool") as factory:
        yield generator, prompt, factory.return_value


def test_result_wait_polls_without_losing_outputs(parallel_generation):
    """A polling timeout is not a failed generation or an extra request."""
    generator, prompt, pool = parallel_generation
    results = [[Message("hello")], [None]]
    iterator = pool.imap_unordered.return_value
    iterator.__iter__.return_value = iter(results)
    iterator.next.side_effect = [TimeoutError(), *results]

    outputs = generator.generate(prompt, generations_this_call=2)

    assert outputs == [results[0][0], None], "Polling must retain every result"
    assert iterator.next.call_count == 3, "A timeout must retry the result wait"
    for call in iterator.next.call_args_list:
        assert 0 < call.kwargs["timeout"] <= 1, "Result waits must be bounded"
    pool.imap_unordered.assert_called_once_with(generator._call_model, [prompt] * 2)
    pool.terminate.assert_not_called()
    pool.close.assert_called_once_with()
    pool.join.assert_called_once_with()


@pytest.mark.parametrize("during_wait", [True, False])
def test_interrupt_terminates_workers(parallel_generation, during_wait):
    """Cancellation must propagate after terminating and joining workers."""
    generator, prompt, pool = parallel_generation
    iterator = pool.imap_unordered.return_value
    iterator.__iter__.return_value = iter([[Message("hello")]])
    if during_wait:
        iterator.__iter__.side_effect = KeyboardInterrupt
        iterator.next.side_effect = KeyboardInterrupt
    else:
        iterator.next.return_value = [Message("hello")]

    with patch.object(
        generator, "_verify_target_result", side_effect=KeyboardInterrupt
    ):
        with pytest.raises(KeyboardInterrupt):
            generator.generate(prompt, generations_this_call=2)

    pool.terminate.assert_called_once_with()
    pool.close.assert_not_called()
    pool.join.assert_called_once_with()
    assert [call[0] for call in pool.method_calls][-2:] == [
        "terminate",
        "join",
    ], "Workers must be terminated before joining"


def test_invalid_result_terminates_remaining_workers(parallel_generation):
    """Validation failure must not wait for unrelated in-flight requests."""
    generator, prompt, pool = parallel_generation
    iterator = pool.imap_unordered.return_value
    iterator.__iter__.return_value = iter([[]])
    iterator.next.return_value = []

    with pytest.raises(AssertionError, match="list of one item"):
        generator.generate(prompt, generations_this_call=2)

    pool.terminate.assert_called_once_with()
    pool.close.assert_not_called()
    pool.join.assert_called_once_with()


def test_interrupt_disconnects_inflight_http_requests(tmp_path):
    """Exercise spawned workers and SIGINT without interrupting pytest itself."""
    script = tmp_path / "cancel_requests.py"
    script.write_text(
        textwrap.dedent('''\
            import _thread
            import http.client
            from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
            import multiprocessing
            import queue
            import threading
            import time

            from garak.attempt import Conversation, Message, Turn
            from garak.generators.base import Generator


            class WaitingGenerator(Generator):
                """Wait for an HTTP response that the test server never sends."""

                def _call_model(self, prompt, generations_this_call=1):
                    connection = http.client.HTTPConnection(self.name, timeout=10)
                    try:
                        connection.request("GET", "/")
                        connection.getresponse()
                    finally:
                        connection.close()
                    return [Message("unexpected response")]


            if __name__ == "__main__":
                multiprocessing.set_start_method("spawn")
                disconnected = queue.Queue()
                interrupted_at = []

                def interrupt():
                    interrupted_at.append(time.monotonic())
                    _thread.interrupt_main()

                ready = threading.Barrier(2, action=interrupt)

                class Handler(BaseHTTPRequestHandler):
                    def do_GET(self):
                        self.connection.settimeout(10)
                        ready.wait(timeout=10)
                        try:
                            disconnected.put(self.connection.recv(1) == b"")
                        except ConnectionResetError:
                            disconnected.put(True)

                with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                    generator = WaitingGenerator(name=f"127.0.0.1:{server.server_port}")
                    generator.parallel_requests = 2
                    generator.max_workers = 2
                    prompt = Conversation([Turn("user", Message("hello"))])
                    try:
                        generator.generate(prompt, generations_this_call=2)
                    except KeyboardInterrupt:
                        assert time.monotonic() - interrupted_at[0] < 5, (
                            "Cancellation must not wait for the HTTP timeout"
                        )
                    else:
                        raise AssertionError("Cancellation must propagate")
                    finally:
                        server.shutdown()

                    for _ in range(2):
                        assert disconnected.get(timeout=5), "HTTP socket must close"
                    assert not multiprocessing.active_children(), "Workers must exit"
                print("cancelled and disconnected")
            '''),
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert (
        result.returncode == 0
    ), f"Cancellation failed: {result.stdout}\n{result.stderr}"
    assert (
        "cancelled and disconnected" in result.stdout
    ), "Both requests must disconnect"
