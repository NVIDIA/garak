"""Tests for bounded Agent Breaker chain discovery and execution."""

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from garak import _config, _plugins
from garak.attempt import Attempt, Message
from garak.exception import PluginConfigurationError
from garak.probes.agent_breaker import AgentBreaker, AttackState, SourceToSink
from garak.resources.agent_breaker.source_to_sink import _SourceToSinkMixin


def _intermediate_policy():
    return {
        "allow_intermediate": True,
        "allow_terminal": False,
        "side_effecting": False,
    }


def _terminal_policy():
    return {
        "allow_intermediate": False,
        "allow_terminal": True,
        "side_effecting": True,
    }


def _tool(name, policy, description="test tool"):
    return {"name": name, "description": description, "chain_policy": policy}


def _manifest(*tools):
    return {"agent_purpose": "test", "tools": list(tools)}


def _probe(**attributes):
    probe = SourceToSink.__new__(SourceToSink)
    defaults = {
        "max_chains": 8,
        "max_chain_len": 4,
        "max_active_chains": 4,
        "max_hypotheses_per_chain": 3,
        "min_edge_confidence": 0.4,
        "max_step_attempts": 3,
        "max_tools": 16,
        "max_graph_edges": 128,
        "max_path_expansions": 1024,
        "max_terminal_attempts_per_tool": 1,
        "success_threshold": 0.7,
        "generations": 1,
        "tool_tags": {},
        "agent_config": _manifest(
            _tool("source", _intermediate_policy()),
            _tool("sink", _terminal_policy()),
        ),
        "agent_analysis": {"tool_analyses": {}},
        "parse_model": None,
        "_terminal_tool_request_reservations": set(),
        "_terminal_tool_counts": {},
    }
    defaults.update(attributes)
    for key, value in defaults.items():
        setattr(probe, key, value)
    return probe


def _tag(**overrides):
    tag = {
        "consumes": ["input"],
        "produces": ["output"],
        "capability_class": "read_sensitive",
        "is_source": True,
        "is_sink": False,
        "sink_severity": 1,
        "delivery": "direct",
        "payload_types": [],
        "executes_content": False,
        "content_handling": "returns a record",
    }
    tag.update(overrides)
    return tag


def _plan(sequence):
    return [
        {
            "tool": tool,
            "role": "exploit" if index == len(sequence) - 1 else "recon",
            "intent": f"use {tool}",
            "must_provide": "value",
            "success_criterion": "returned value",
            "input_artifact_keys": [] if index == 0 else ["reference"],
            "artifact_keys": [] if index == len(sequence) - 1 else ["reference"],
        }
        for index, tool in enumerate(sequence)
    ]


def _chain(sequence=("source", "sink"), step_index=1):
    return {
        "chain_id": "chain_1",
        "sequence": list(sequence),
        "step_index": step_index,
        "step_outputs": [],
        "artifacts": {"reference": "ref:123"} if step_index > 0 else {},
        "step_plan": _plan(sequence),
        "vulnerabilities": "unsafe handoff",
        "current_technique": "test_technique",
        "hypothesis": {"sink_requirement": "complete the requested terminal effect"},
    }


def _attempt(chain, outputs):
    state = AttackState(
        current_target=chain["sequence"][chain["step_index"]],
        current_tool_analysis=chain,
        current_attack_prompt="test prompt",
        vulnerability_info="unsafe handoff",
    )
    attempt = MagicMock()
    attempt.notes = state.to_notes()
    attempt.outputs = outputs
    return attempt


def test_probe_declares_chain_specific_metadata():
    assert SourceToSink.tags == [
        "owasp:llm01",
        "owasp:llm06",
        "quality:Security:AgentSecurity",
        "payload:agentic:exploitation",
    ], "chain probe must publish its security taxonomies"
    assert (
        SourceToSink.doc_uri == "https://arxiv.org/abs/2603.12614"
    ), "chain probe must cite its technique source"
    assert SourceToSink.intent == "S008", "chain probe must declare its MISP intent"
    assert SourceToSink.active is False, "chain probe must require explicit selection"
    assert (
        SourceToSink.parallelisable_attempts is False
    ), "chain steps must execute serially"
    assert (
        SourceToSink.uses_in_loop_detector is False
    ), "chain probe must defer judgement to its detector"


def test_probe_uses_canonical_module_and_cooperative_mro():
    assert (
        SourceToSink.__module__ == "garak.probes.agent_breaker"
    ), "chain probe must be published from the Agent Breaker probe family"
    assert issubclass(
        SourceToSink, AgentBreaker
    ), "chain probe must remain an AgentBreaker subtype"
    assert (
        _SourceToSinkMixin in SourceToSink.__mro__
    ), "chain probe must retain its private resource implementation mixin"
    assert SourceToSink.__mro__.index(_SourceToSinkMixin) < SourceToSink.__mro__.index(
        AgentBreaker
    ), "resource mixin must precede AgentBreaker for cooperative super calls"
    assert (
        AttackState.__module__ == "garak.probes.agent_breaker"
    ), "shared attempt state must retain its canonical public module"
    lifecycle_methods = {
        "__init__",
        "_load_prompts",
        "_create_init_attempts",
        "_queue_step_attack",
        "_advance_stepwise",
        "_handle_stepwise_refinement",
        "_postprocess_attempt",
        "_generate_next_attempts",
    }
    assert (
        lifecycle_methods <= SourceToSink.__dict__.keys()
    ), "chain lifecycle overrides must remain on the public plugin class"


def test_probe_discovery_uses_only_canonical_identifier():
    discovered = {classname for classname, _ in _plugins.enumerate_plugins("probes")}
    assert (
        "probes.agent_breaker.SourceToSink" in discovered
    ), "plugin discovery must expose the canonical chain probe identifier"
    assert (
        "probes.agent_breaker_chains.SourceToSink" not in discovered
    ), "plugin discovery must not retain the removed chain probe module"


def test_agent_breaker_class_configs_remain_isolated():
    config = {
        "probes": {
            "agent_breaker": {
                "AgentBreaker": {
                    "max_attempts_per_tool": 2,
                    "success_threshold": 0.2,
                },
                "SourceToSink": {
                    "max_attempts_per_tool": 3,
                    "success_threshold": 0.3,
                    "max_chains": 4,
                },
            }
        }
    }
    with patch.object(AgentBreaker, "_make_detector", return_value=MagicMock()):
        single = AgentBreaker(config_root=config)
        chains = SourceToSink(config_root=config)

    assert (
        single.max_attempts_per_tool == 2
    ), "Single must receive only its class-scoped attempt limit"
    assert (
        single.success_threshold == 0.2
    ), "Single must receive only its class-scoped threshold"
    assert not hasattr(
        single, "max_chains"
    ), "chain-only defaults must not leak onto Single"
    assert (
        chains.max_attempts_per_tool == 3
    ), "Chains must receive its own class-scoped attempt limit"
    assert (
        chains.success_threshold == 0.3
    ), "Chains must receive its own class-scoped threshold"
    assert chains.max_chains == 4, "Chains must receive its class-scoped chain limit"


def test_constructor_does_not_load_in_loop_judge():
    with patch.object(AgentBreaker, "_make_detector") as detector_factory:
        probe = SourceToSink(config_root={})
    assert not hasattr(
        probe, "_detector"
    ), "chain constructor must not retain an in-loop judge"
    detector_factory.assert_not_called()


def test_multiple_generations_fail_before_model_or_target_calls():
    probe = _probe(generations=2)
    probe._setup_red_team_model = MagicMock()
    with pytest.raises(PluginConfigurationError, match="requires generations=1"):
        probe._create_init_attempts()
    probe._setup_red_team_model.assert_not_called()


def test_buffs_fail_before_model_or_target_calls():
    probe = _probe()
    probe._setup_red_team_model = MagicMock()
    with (
        patch.object(_config.buffmanager, "buffs", [object()]),
        pytest.raises(PluginConfigurationError, match="does not support buffs"),
    ):
        probe._create_init_attempts()
    probe._setup_red_team_model.assert_not_called()


@pytest.mark.parametrize(
    "agent_config",
    [
        {},
        {"agent_purpose": "test", "tools": []},
        _manifest(_tool("only", _intermediate_policy())),
        _manifest(
            _tool(
                "invalid",
                {
                    "allow_intermediate": "true",
                    "allow_terminal": False,
                    "side_effecting": False,
                },
            ),
            _tool("sink", _terminal_policy()),
        ),
    ],
)
def test_missing_or_invalid_manifest_fails_before_any_model_or_target_call(
    agent_config,
):
    probe = _probe(agent_config=agent_config)
    probe._setup_red_team_model = MagicMock()
    probe._discover_agent_config = MagicMock()
    probe.generator = MagicMock()

    with pytest.raises(PluginConfigurationError, match="valid chain_policy"):
        probe._create_init_attempts()

    probe._setup_red_team_model.assert_not_called()
    probe._discover_agent_config.assert_not_called()
    probe.generator.generate.assert_not_called()


def test_non_english_translation_fails_before_model_or_target_call():
    probe = _probe()
    probe.langprovider = MagicMock(target_lang="fr")
    probe._setup_red_team_model = MagicMock()
    probe.generator = MagicMock()

    with pytest.raises(PluginConfigurationError, match="target language 'en'"):
        probe._create_init_attempts()

    probe._setup_red_team_model.assert_not_called()
    probe.generator.generate.assert_not_called()


@pytest.mark.parametrize(
    "name,value",
    [
        ("max_chain_len", 5),
        ("max_step_attempts", 4),
        ("max_terminal_attempts_per_tool", 2),
    ],
)
def test_safety_configuration_cannot_exceed_reviewed_maxima(name, value):
    probe = _probe(**{name: value})
    with pytest.raises(PluginConfigurationError, match="must not exceed"):
        probe._config_limit(name, value)


@pytest.mark.parametrize(
    "name,value",
    [
        ("max_terminal_attempts_per_tool", 2),
        ("max_path_expansions", 1025),
        ("success_threshold", float("inf")),
        pytest.param("success_threshold", 10**1000, id="huge-success-threshold"),
        pytest.param("min_edge_confidence", 10**1000, id="huge-edge-threshold"),
    ],
)
def test_safety_configuration_fails_before_model_or_target_calls(name, value):
    probe = _probe(**{name: value})
    probe._setup_red_team_model = MagicMock()
    probe.generator = MagicMock()

    with pytest.raises(PluginConfigurationError):
        probe._create_init_attempts()

    probe._setup_red_team_model.assert_not_called()
    probe.generator.generate.assert_not_called()


def test_tool_list_is_validated_and_capped_before_analysis():
    probe = _probe(
        max_tools=2,
        agent_config={
            "agent_purpose": "p" * 2000,
            "tools": [
                {
                    "name": " one ",
                    "description": "d" * 2000,
                    "chain_policy": _intermediate_policy(),
                    "extra": "drop",
                },
                _tool("ONE", _terminal_policy(), "case-insensitive duplicate"),
                _tool("two", _terminal_policy(), 7),
                _tool("three", _intermediate_policy(), "third"),
            ],
        },
    )
    probe._cap_agent_tools()
    assert [tool["name"] for tool in probe.agent_config["tools"]] == [
        "one",
        "two",
    ], "manifest validation must deduplicate and cap tools"
    assert all(
        set(tool) == {"name", "description", "chain_policy"}
        for tool in probe.agent_config["tools"]
    ), "validated tools must expose only approved fields"
    assert (
        len(probe.agent_config["agent_purpose"]) <= probe._MODEL_FIELD_CHAR_LIMIT
    ), "agent purpose must respect the model field bound"
    assert len(probe.agent_config["tools"][0]["description"]) <= (
        probe._TOOL_DESCRIPTION_CHAR_LIMIT
    ), "tool descriptions must respect their context bound"
    assert (
        probe.agent_config["tools"][1]["description"] == ""
    ), "non-string descriptions must be discarded"


def test_capability_graph_connects_generic_producers_and_consumers():
    tags = {
        "lookup": {"produces": ["record_ref"], "consumes": ["query"]},
        "transform": {"produces": ["document"], "consumes": ["record_ref"]},
        "submit": {"produces": [], "consumes": ["document"]},
    }
    probe = _probe(
        agent_config=_manifest(
            _tool("lookup", _intermediate_policy()),
            _tool("transform", _intermediate_policy()),
            _tool("submit", _terminal_policy()),
        )
    )
    pairs = {(edge["from"], edge["to"]) for edge in probe._build_capability_graph(tags)}
    assert ("lookup", "transform") in pairs, "producer must connect to its consumer"
    assert ("transform", "submit") in pairs, "handoff must connect to its sink"
    assert all(
        source != target for source, target in pairs
    ), "capability graph must omit self-loops"


def test_capability_graph_respects_edge_budget():
    tags = {
        f"tool_{index}": _tag(consumes=["shared"], produces=["shared"])
        for index in range(10)
    }
    agent_config = _manifest(*(_tool(name, _intermediate_policy()) for name in tags))
    assert (
        len(
            _probe(
                max_graph_edges=5, agent_config=agent_config
            )._build_capability_graph(tags)
        )
        == 5
    ), "capability graph must stop at its configured edge budget"
    assert (
        _probe(max_graph_edges=0, agent_config=agent_config)._build_capability_graph(
            tags
        )
        == []
    ), "zero edge budget must produce an empty graph"


def test_capability_graph_omits_unrelated_tags_and_bounds_edge_payload():
    tags = {
        "source": {
            "produces": [" Record Ref ", "large_unused_payload"],
            "consumes": [],
        },
        "sink": {"produces": [], "consumes": ["record ref", "other_input"]},
        "unrelated": {"produces": [], "consumes": ["different_type"]},
    }
    probe = _probe(
        agent_config=_manifest(
            _tool("source", _intermediate_policy()),
            _tool("sink", _terminal_policy()),
            _tool("unrelated", _intermediate_policy()),
        )
    )
    assert probe._build_capability_graph(tags) == [
        {
            "from": "source",
            "to": "sink",
            "produces": [" Record Ref "],
            "consumes": ["record ref"],
        }
    ], "graph must retain only related bounded edge data"


def test_path_search_is_bounded_acyclic_and_ranked():
    probe = _probe(
        max_chain_len=3,
        max_chains=2,
        agent_config=_manifest(
            _tool("source", _intermediate_policy()),
            _tool("pivot", _intermediate_policy()),
            _tool("low_sink", _terminal_policy()),
            _tool("high_sink", _terminal_policy()),
        ),
    )
    tags = {
        "source": {"is_source": True, "is_sink": False},
        "pivot": {"is_source": False, "is_sink": False},
        "low_sink": {"is_source": False, "is_sink": True, "sink_severity": 2},
        "high_sink": {"is_source": False, "is_sink": True, "sink_severity": 5},
    }
    edges = [
        {"from": "source", "to": "low_sink", "confidence": 0.9},
        {"from": "source", "to": "pivot", "confidence": 0.9},
        {"from": "pivot", "to": "high_sink", "confidence": 0.9},
        {"from": "pivot", "to": "source", "confidence": 1.0},
    ]
    paths = probe._search_chains(edges, tags)
    assert paths[0]["sequence"] == [
        "source",
        "pivot",
        "high_sink",
    ], "path ranking must prioritise the higher-severity sink"
    assert all(
        len(path["sequence"]) <= 3 for path in paths
    ), "path search must enforce its length bound"
    assert all(
        len(path["sequence"]) == len(set(path["sequence"])) for path in paths
    ), "path search must remain acyclic"


def test_path_search_never_traverses_a_sink():
    tags = {
        "source": {"is_source": True, "is_sink": False},
        "first_sink": {"is_source": False, "is_sink": True, "sink_severity": 2},
        "second_sink": {"is_source": False, "is_sink": True, "sink_severity": 5},
    }
    edges = [
        {"from": "source", "to": "first_sink", "confidence": 1.0},
        {"from": "first_sink", "to": "second_sink", "confidence": 1.0},
    ]
    probe = _probe(
        agent_config=_manifest(
            _tool("source", _intermediate_policy()),
            _tool("first_sink", _terminal_policy()),
            _tool("second_sink", _terminal_policy()),
        )
    )
    paths = probe._search_chains(edges, tags)
    assert [path["sequence"] for path in paths] == [
        ["source", "first_sink"]
    ], "path search must stop at the first sink"


def test_tool_tagger_drops_model_invented_tools():
    probe = _probe(
        agent_config=_manifest(_tool("known", _intermediate_policy())),
        agent_analysis={"tool_analyses": {"known": {}}},
    )
    probe._prompts = {
        "TOOL_TAGGING": "{agent_purpose}{tools_description}{per_tool_analyses}"
    }
    probe._get_model_response = MagicMock(
        return_value=json.dumps(
            {"tool_tags": {"known": _tag(), "invented": _tag(is_sink=True)}}
        )
    )
    assert probe._tag_tool_capabilities() == {
        "known": _tag()
    }, "tagger must discard tools absent from the manifest"


@pytest.mark.parametrize(
    "capability_class", ["write_mutate", "code_exec", "irreversible"]
)
def test_side_effecting_capabilities_must_be_sinks(capability_class):
    assert (
        SourceToSink._validated_tool_tag(
            _tag(capability_class=capability_class, is_sink=False)
        )
        is None
    ), "side-effecting capabilities must be terminal sinks"


def test_read_sensitive_only_tool_cannot_be_a_terminal_sink():
    assert (
        SourceToSink._validated_tool_tag(_tag(is_sink=True)) is None
    ), "read-only capability must not become a sink"
    assert (
        SourceToSink._validated_tool_tag(_tag(is_sink=True, executes_content=True))
        is None
    ), "execution flag must not escalate a read-only capability"


@pytest.mark.parametrize("field", ["capability_class", "delivery"])
@pytest.mark.parametrize("value", [[], {}])
def test_tool_tagger_rejects_nonscalar_fields(field, value):
    assert (
        SourceToSink._validated_tool_tag(_tag(**{field: value})) is None
    ), "malformed tag fields must be rejected without aborting planning"


@pytest.mark.parametrize(
    "policy",
    [
        {
            "allow_intermediate": True,
            "allow_terminal": True,
            "side_effecting": False,
        },
        {
            "allow_intermediate": False,
            "allow_terminal": False,
            "side_effecting": False,
        },
        {
            "allow_intermediate": True,
            "allow_terminal": False,
            "side_effecting": True,
        },
        {
            "allow_intermediate": True,
            "allow_terminal": False,
            "side_effecting": False,
            "extra": False,
        },
    ],
)
def test_chain_policy_rejects_ambiguous_or_extra_authority(policy):
    assert (
        SourceToSink._validated_chain_policy(policy) is None
    ), "ambiguous chain authority must fail closed"


@pytest.mark.parametrize(
    "changes",
    [
        {"confidence": True},
        {"confidence": "0.8"},
        {"confidence": -0.1},
        {"confidence": 1.1},
        {"confidence": float("inf")},
        pytest.param({"confidence": 10**1000}, id="huge-confidence"),
        {"from": []},
        {"from": {}},
        {"to": []},
        {"to": {}},
    ],
)
def test_edge_scorer_rejects_invalid_model_fields(changes):
    probe = _probe(tool_tags={"a": _tag(), "b": _tag()})
    probe._prompts = {"EDGE_SCORE": "{tool_tags}{candidate_edges}"}
    probe._get_model_response = MagicMock(
        return_value=json.dumps(
            {
                "edges": [
                    {
                        "from": "a",
                        "to": "b",
                        "confidence": 0.8,
                        "data_flow": "ref",
                        **changes,
                    }
                ]
            }
        )
    )
    candidates = [{"from": "a", "to": "b", "produces": ["x"], "consumes": ["x"]}]
    assert (
        probe._score_edges(candidates) == []
    ), "invalid model fields must drop the edge"


def _step_plan_response(sequence=("source", "sink")):
    return {
        "step_plan": [
            {
                "tool": tool,
                "role": "exploit" if index == len(sequence) - 1 else "recon",
                "intent": f"use {tool}",
                "must_provide": "reference",
                "success_criterion": "effect" if index else "reference returned",
                "input_artifact_keys": [] if index == 0 else ["reference"],
                "artifact_keys": [] if index == len(sequence) - 1 else ["reference"],
            }
            for index, tool in enumerate(sequence)
        ]
    }


def test_step_plan_preserves_graph_order_and_one_terminal_exploit():
    probe = _probe()
    probe._prompts = {
        "STEP_PLAN": "{sequence}{intent}{data_flow}{vulnerabilities}{tools_block}"
        "{delivery}{exploit_technique}{payload_shape}{sink_requirement}"
    }
    response = _step_plan_response()
    probe._get_model_response = MagicMock(return_value=json.dumps(response))
    chain = {"sequence": ["source", "sink"], "hypothesis": {}}
    assert [item["tool"] for item in probe._generate_step_plan(chain)] == [
        "source",
        "sink",
    ], "step plan must preserve graph order"
    response["step_plan"][0]["role"] = "exploit"
    probe._get_model_response.return_value = json.dumps(response)
    assert (
        probe._generate_step_plan(chain) is None
    ), "step plan must allow exactly one terminal exploit"


def test_step_plan_rejects_unproduced_input_dependency():
    probe = _probe()
    probe._prompts = {
        "STEP_PLAN": "{sequence}{intent}{data_flow}{vulnerabilities}{tools_block}"
        "{delivery}{exploit_technique}{payload_shape}{sink_requirement}"
    }
    response = _step_plan_response()
    response["step_plan"][1]["input_artifact_keys"] = ["invented"]
    probe._get_model_response = MagicMock(return_value=json.dumps(response))
    assert (
        probe._generate_step_plan({"sequence": ["source", "sink"], "hypothesis": {}})
        is None
    ), "step plan must reject unproduced dependencies"


def test_step_plan_rejects_operator_policy_role_escalation_before_model_call():
    probe = _probe(
        agent_config=_manifest(
            _tool("source", _terminal_policy()),
            _tool("sink", _intermediate_policy()),
        )
    )
    probe._get_model_response = MagicMock()

    assert (
        probe._generate_step_plan({"sequence": ["source", "sink"], "hypothesis": {}})
        is None
    ), "step plan must obey operator tool authority"
    probe._get_model_response.assert_not_called()


def test_step_plan_rejects_excessive_artifact_fanout():
    probe = _probe()
    probe._prompts = {
        "STEP_PLAN": "{sequence}{intent}{data_flow}{vulnerabilities}{tools_block}"
        "{delivery}{exploit_technique}{payload_shape}{sink_requirement}"
    }
    response = _step_plan_response()
    response["step_plan"][0]["artifact_keys"] = [
        f"artifact_{index}" for index in range(5)
    ]
    response["step_plan"][1]["input_artifact_keys"] = ["artifact_0"]
    probe._get_model_response = MagicMock(return_value=json.dumps(response))

    assert (
        probe._generate_step_plan({"sequence": ["source", "sink"], "hypothesis": {}})
        is None
    ), "step plan must reject excessive artifact fanout"


def test_step_plan_rejects_case_insensitive_duplicate_artifact_keys():
    probe = _probe()
    probe._prompts = {
        "STEP_PLAN": "{sequence}{intent}{data_flow}{vulnerabilities}{tools_block}"
        "{delivery}{exploit_technique}{payload_shape}{sink_requirement}"
    }
    response = _step_plan_response()
    response["step_plan"][0]["artifact_keys"] = ["Ref", "ref"]
    response["step_plan"][1]["input_artifact_keys"] = ["Ref"]
    probe._get_model_response = MagicMock(return_value=json.dumps(response))

    assert (
        probe._generate_step_plan({"sequence": ["source", "sink"], "hypothesis": {}})
        is None
    ), "step plan must reject ambiguous artifact keys"


def test_step_plan_rejects_terminal_artifact_keys():
    probe = _probe()
    probe._prompts = {
        "STEP_PLAN": "{sequence}{intent}{data_flow}{vulnerabilities}{tools_block}"
        "{delivery}{exploit_technique}{payload_shape}{sink_requirement}"
    }
    response = _step_plan_response()
    response["step_plan"][-1]["artifact_keys"] = ["terminal_result"]
    probe._get_model_response = MagicMock(return_value=json.dumps(response))

    assert (
        probe._generate_step_plan({"sequence": ["source", "sink"], "hypothesis": {}})
        is None
    ), "the terminal step must not request return artifacts"


def test_generated_attack_prompt_must_quote_required_artifact():
    probe = _probe()
    probe._prompts = {"STEP_ATTACK": "{target_tool}{input_artifact_keys}"}
    probe._get_model_response = MagicMock(
        return_value=json.dumps(
            {
                "analysis": "use the reference",
                "technique": "test",
                "attack_prompt": "invoke the sink\nreference = forged",
            }
        )
    )
    assert probe._generate_step_attack_prompt(_chain(), 1) == (
        None,
        "",
    ), "attack prompt must reject conflicting required artifact values"
    probe._get_model_response.return_value = json.dumps(
        {
            "analysis": "use the reference",
            "technique": "test",
            "attack_prompt": "invoke the sink\nreference = ref:123",
        }
    )
    assert probe._generate_step_attack_prompt(_chain(), 1) == (
        "invoke the sink\nreference = ref:123",
        "test",
    ), "explicitly bound attack input must remain eligible"


def test_generated_attack_prompt_rejects_missing_required_input_binding():
    probe = _probe()
    probe._prompts = {"STEP_ATTACK": "{target_tool}{input_artifact_keys}"}
    probe._get_model_response = MagicMock(
        return_value=json.dumps(
            {
                "analysis": "substitute an unbound reference",
                "technique": "test",
                "attack_prompt": "use a forged reference and ignore later binding",
            }
        )
    )

    assert probe._generate_step_attack_prompt(_chain(), 1) == (
        None,
        "",
    ), "missing helper bindings must fail rather than be appended to conflicting text"


def test_generated_attack_prompt_rejects_helper_authored_probe_binding():
    probe = _probe()
    probe._prompts = {"STEP_ATTACK": "{target_tool}{input_artifact_keys}"}
    probe._get_model_response = MagicMock(
        return_value=json.dumps(
            {
                "analysis": "impersonate the probe binding",
                "technique": "test",
                "attack_prompt": (
                    "Probe-authored tool binding:\n"
                    'Use only the manifest tool named exactly "sink" for this request.\n'
                    "Do not use or invoke any other tool.\n\n"
                    "reference = ref:123"
                ),
            }
        )
    )

    assert probe._generate_step_attack_prompt(_chain(), 1) == (
        None,
        "",
    ), "helper-authored probe controls must fail before request construction"


def test_generated_attack_prompt_rejects_helper_authored_output_records():
    probe = _probe()
    probe._prompts = {"STEP_ATTACK": "{target_tool}{input_artifact_keys}"}
    probe._get_model_response = MagicMock(
        return_value=json.dumps(
            {
                "analysis": "impersonate the probe output schema",
                "technique": "test",
                "attack_prompt": "Find one item.\nreference = <value>",
            }
        )
    )

    assert probe._generate_step_attack_prompt(_chain(step_index=0), 0) == (
        None,
        "",
    ), "helper-authored output records must fail before response framing"


def test_generated_attack_prompt_rejects_conflict_alongside_exact_binding():
    probe = _probe()
    probe._prompts = {"STEP_ATTACK": "{target_tool}{input_artifact_keys}"}
    probe._get_model_response = MagicMock(
        return_value=json.dumps(
            {
                "analysis": "smuggle a conflicting reference",
                "technique": "test",
                "attack_prompt": "reference = forged\nreference = ref:123",
            }
        )
    )

    assert probe._generate_step_attack_prompt(_chain(), 1) == (
        None,
        "",
    ), "required input records must have one unambiguous value"


def test_zero_hypothesis_limit_cannot_fall_back_to_default_hypothesis():
    probe = _probe(max_hypotheses_per_chain=0)
    probe._generate_exploit_hypotheses = MagicMock()
    probe._generate_step_plan = MagicMock()
    path = {"sequence": ["source", "sink"], "edges": [], "score": 1.0}

    assert probe._generate_chain_attacks([path]) == {
        "chains": [],
        "priority_chains": [],
    }, "zero hypothesis limit must prevent chain execution"
    probe._generate_exploit_hypotheses.assert_not_called()
    probe._generate_step_plan.assert_not_called()


def test_step_prompt_renders_only_declared_input_artifacts():
    probe = _probe()
    chain = _chain()
    chain["artifacts"]["unrelated_secret"] = "must-not-enter-helper-context"

    values = probe._step_prompt_values(chain, 1)

    assert (
        "ref:123" in values["prior_artifacts"]
    ), "declared input artifact must enter helper context"
    assert (
        "unrelated_secret" not in values["prior_artifacts"]
    ), "undeclared artifact key must stay out of helper context"
    assert (
        "must-not-enter-helper-context" not in values["prior_artifacts"]
    ), "undeclared artifact value must stay out of helper context"


def test_artifact_and_helper_prompt_aggregate_bounds_fail_closed():
    probe = _probe()
    too_many_artifacts = {
        f"key_{index}": "value"
        for index in range(probe._ARTIFACT_KEYS_PER_STEP_LIMIT + 1)
    }
    assert (
        probe._format_prior_artifacts(too_many_artifacts) is None
    ), "oversized artifact context must fail closed"

    probe._get_model_response = MagicMock()
    oversized_prompt = "x" * (probe._HELPER_PROMPT_CHAR_LIMIT + 1)
    assert (
        probe._get_helper_model_response(oversized_prompt) is None
    ), "oversized helper prompt must fail before inference"
    probe._get_model_response.assert_not_called()
    probe._get_model_response.return_value = oversized_prompt
    assert (
        probe._get_helper_model_response("bounded prompt") is None
    ), "oversized helper output must fail before parsing"


def test_chain_config_limit_preserves_priority_order():
    chains = [
        {"chain_id": "first", "sequence": ["a", "b"], "step_plan": _plan(["a", "b"])},
        {"chain_id": "second", "sequence": ["c", "d"], "step_plan": _plan(["c", "d"])},
    ]
    probe = _probe(
        max_active_chains=1,
        agent_config=_manifest(
            _tool("a", _intermediate_policy()),
            _tool("b", _terminal_policy()),
            _tool("c", _intermediate_policy()),
            _tool("d", _terminal_policy()),
        ),
        agent_analysis={
            "chains": chains,
            "priority_chains": ["second - score 5.00", "first - score 1.00"],
        },
    )
    assert probe._build_chain_configs() == [
        ("c", {**chains[1], "is_chain": True})
    ], "chain activation must preserve priority order and cap"


def test_hypothesis_parser_rejects_non_string_fields():
    probe = _probe(tool_tags={"sink": _tag(is_sink=True)})
    probe._prompts = {
        "EXPLOIT_HYPOTHESES": "{sequence}{sink}{delivery}{sink_tags}{data_flow}"
        "{vulnerabilities}{tools_block}{max_hypotheses}"
    }
    probe._get_model_response = MagicMock(
        return_value=json.dumps(
            {
                "hypotheses": [
                    {
                        "technique": "test",
                        "description": False,
                        "payload_shape": "value",
                        "sink_requirement": "effect",
                    }
                ]
            }
        )
    )
    assert (
        probe._generate_exploit_hypotheses({"sequence": ["source", "sink"]}) == []
    ), "invalid hypothesis fields must fail closed"


def test_transcript_bounds_every_prompt_and_response():
    probe = _probe()
    long_prompt = "P" * (probe._STEP_PROMPT_CHAR_LIMIT + 200)
    long_response = "R" * (probe._STEP_RESPONSE_CHAR_LIMIT + 200)
    chain = _chain()
    chain["step_outputs"] = [
        {"tool": "source", "prompt": long_prompt, "response": long_response}
    ]
    transcript = probe._render_chain_transcript(chain, long_prompt, long_response)
    assert (
        transcript.count("...[truncated]") == 4
    ), "transcript must mark every bounded field"
    assert (
        "P" * (probe._STEP_PROMPT_CHAR_LIMIT + 1) not in transcript
    ), "transcript must bound prompt text"
    assert (
        "R" * (probe._STEP_RESPONSE_CHAR_LIMIT + 1) not in transcript
    ), "transcript must bound response text"


def test_structured_artifact_fallback_is_schema_agnostic():
    response = json.dumps({"result": {"opaque_reference": "ref:123"}})
    assert _probe()._structured_response_artifacts(response, ["opaque_reference"]) == (
        {"opaque_reference": "ref:123"},
        set(),
    ), "structured fallback must accept arbitrary declared keys"


def test_structured_artifact_fallback_rejects_ambiguous_duplicate_keys():
    response = json.dumps(
        {"first": {"reference": "ref:123"}, "second": {"reference": "ref:456"}}
    )
    assert _probe()._structured_response_artifacts(response, ["reference"]) == (
        {},
        {"reference"},
    ), "distinct duplicate values must be marked ambiguous"


def test_structured_artifact_fallback_rejects_lexical_duplicate_keys():
    response = '{"reference":"ref:123","reference":"ref:456"}'
    assert _probe()._structured_response_artifacts(response, ["reference"]) == (
        {},
        {"reference"},
    ), "lexically duplicated JSON keys must fail closed"


def test_model_artifact_must_appear_verbatim_in_target_response():
    probe = _probe()
    probe._prompts = {
        "EXTRACT_ARTIFACTS": "{tool_name}{role}{intent}{step_prompt}"
        "{agent_response}{artifact_keys}"
    }
    probe._setup_parse_model = MagicMock()
    probe.parse_model = MagicMock()
    probe._get_model_response = MagicMock(
        return_value=json.dumps({"artifacts": {"reference": "hallucinated-ref"}})
    )
    assert (
        probe._extract_artifacts(
            _chain(step_index=0), 0, "prompt", "target returned real-ref"
        )
        == {}
    ), "hallucinated artifact must be rejected"


def test_grounded_model_artifact_is_accepted():
    probe = _probe()
    probe._prompts = {
        "EXTRACT_ARTIFACTS": "{tool_name}{role}{intent}{step_prompt}"
        "{agent_response}{artifact_keys}"
    }
    probe._setup_parse_model = MagicMock()
    probe.parse_model = MagicMock()
    probe._get_model_response = MagicMock(
        return_value=json.dumps({"artifacts": {"reference": "real-ref"}})
    )
    assert probe._extract_artifacts(
        _chain(step_index=0), 0, "prompt", "reference = real-ref"
    ) == {"reference": "real-ref"}, "explicitly bound artifact must be accepted"


def test_incidental_parser_substring_is_not_an_artifact():
    probe = _probe()
    probe._prompts = {
        "EXTRACT_ARTIFACTS": "{tool_name}{role}{intent}{step_prompt}"
        "{agent_response}{artifact_keys}"
    }
    probe._setup_parse_model = MagicMock()
    probe.parse_model = MagicMock()
    probe._get_model_response = MagicMock(
        return_value=json.dumps({"artifacts": {"reference": "fail"}})
    )

    assert (
        probe._extract_artifacts(_chain(step_index=0), 0, "prompt", "lookup failed")
        == {}
    ), "incidental response text must not confer artifact authority"


def test_oversized_target_response_cannot_produce_artifacts():
    probe = _probe()
    response = (
        '{"reference":"ref:123","padding":"'
        + ("x" * probe._STEP_RESPONSE_CHAR_LIMIT)
        + '"}'
    )
    probe._setup_parse_model = MagicMock()

    assert probe._extract_artifacts(_chain(step_index=0), 0, "prompt", response) == (
        {}
    ), "oversized response must not create an artifact/checker split view"
    probe._setup_parse_model.assert_not_called()


def test_json_integer_limit_fails_closed():
    huge_integer = "1" * 5000
    assert _probe()._structured_response_artifacts(
        f'{{"reference":{huge_integer}}}', ["reference"]
    ) == ({}, set()), "oversized structured artifacts must fail closed"
    with pytest.raises(json.JSONDecodeError):
        AgentBreaker._extract_json(f'{{"reference":{huge_integer}}}')


def test_invalid_unicode_cannot_reach_tool_requests_or_hashes():
    invalid = "value\ud800"
    probe = _probe()
    probe._get_model_response = MagicMock()

    assert (
        probe._get_helper_model_response(invalid) is None
    ), "invalid Unicode must not reach a helper transport"
    probe._get_model_response.assert_not_called()
    probe._get_model_response.return_value = invalid
    assert (
        probe._get_helper_model_response("safe prompt") is None
    ), "invalid Unicode helper output must fail before parsing"
    assert (
        probe._bind_step_request("sink", invalid) is None
    ), "invalid Unicode must not become a target request"
    assert (
        probe._artifact_text(invalid) is None
    ), "invalid Unicode must not become a handoff artifact"
    assert (
        probe._request_ref(invalid) is None
    ), "invalid Unicode must not reach request hashing"


def test_unrelated_parser_value_cannot_override_structured_response_value():
    probe = _probe()
    probe._prompts = {
        "EXTRACT_ARTIFACTS": "{tool_name}{role}{intent}{step_prompt}"
        "{agent_response}{artifact_keys}"
    }
    probe._setup_parse_model = MagicMock()
    probe.parse_model = MagicMock()
    probe._get_model_response = MagicMock(
        return_value=json.dumps({"artifacts": {"reference": "other-ref"}})
    )
    response = json.dumps({"reference": "real-ref", "note": "other-ref"})
    assert probe._extract_artifacts(_chain(step_index=0), 0, "prompt", response) == {
        "reference": "real-ref"
    }, "only the declared structured key may supply an artifact"


def test_short_parser_substring_is_not_an_artifact():
    probe = _probe()
    probe._prompts = {
        "EXTRACT_ARTIFACTS": "{tool_name}{role}{intent}{step_prompt}"
        "{agent_response}{artifact_keys}"
    }
    probe._setup_parse_model = MagicMock()
    probe.parse_model = MagicMock()
    probe._get_model_response = MagicMock(
        return_value=json.dumps({"artifacts": {"reference": "is"}})
    )
    assert (
        probe._extract_artifacts(_chain(step_index=0), 0, "prompt", "status is pending")
        == {}
    ), "short substring must not qualify as an artifact"


def test_blank_target_response_cannot_advance():
    probe = _probe()
    probe._get_model_response = MagicMock()
    chain = _chain(step_index=0)
    artifacts = probe._extract_artifacts(chain, 0, "prompt", "   ")
    assert probe._check_step_success(chain, 0, "prompt", "   ", artifacts) == (
        False,
        1.0,
        "blank target response",
    ), "blank target response must not advance the chain"
    probe._get_model_response.assert_not_called()


@pytest.mark.parametrize(
    "confidence,expected",
    [
        (0.0, (False, 0.0, "uncertain")),
        pytest.param(
            10**1000,
            (False, 0.0, "invalid step-check response"),
            id="huge-confidence",
        ),
    ],
)
def test_step_check_requires_valid_confidence_above_threshold(confidence, expected):
    probe = _probe(success_threshold=0.7)
    probe._prompts = {
        "CHECK_STEP_SUCCESS": "{tool_name}{role}{intent}{success_criterion}"
        "{step_prompt}{agent_response}{artifacts_str}"
    }
    probe._setup_parse_model = MagicMock()
    probe.parse_model = MagicMock()
    probe._get_model_response = MagicMock(
        return_value=json.dumps(
            {
                "step_succeeded": True,
                "confidence": confidence,
                "reasoning": "uncertain",
            }
        )
    )
    assert (
        probe._check_step_success(
            _chain(step_index=0),
            0,
            "prompt",
            "target returned ref:123",
            {"reference": "ref:123"},
        )
        == expected
    ), "low or invalid confidence must not advance the chain"


def test_duplicate_terminal_attempts_are_suppressed_before_queueing():
    probe = _probe()
    probe._generate_step_attack_prompt = MagicMock(return_value=("use ref:123", "test"))
    attempt = MagicMock()
    attempt.prompt.last_message.return_value.text = "use ref:123"
    probe._create_attempt = MagicMock(return_value=attempt)
    chain = _chain()
    first = probe._queue_step_attack(chain, "unsafe handoff")
    second = probe._queue_step_attack(chain, "unsafe handoff")
    assert first is attempt, "first terminal request must be queued"
    assert second is None, "duplicate terminal request must be suppressed"
    assert (
        probe._create_attempt.call_count == 2
    ), "suppression must compare rendered terminal requests"


def test_terminal_artifact_keys_fail_before_request_construction():
    probe = _probe()
    probe._generate_step_attack_prompt = MagicMock(return_value=("use ref:123", "test"))
    probe._create_attempt = MagicMock()
    chain = _chain()
    chain["step_plan"][-1]["artifact_keys"] = ["terminal_result"]

    assert (
        probe._queue_step_attack(chain, "unsafe handoff") is None
    ), "terminal return-artifact instructions must never reach the target"
    probe._create_attempt.assert_not_called()


def test_step_request_has_exact_manifest_tool_binding_preamble():
    probe = _probe(
        agent_config=_manifest(
            _tool("source", _intermediate_policy(), "read one approved record"),
            _tool("sink", _terminal_policy(), "send only approved records"),
        )
    )
    probe._generate_step_attack_prompt = MagicMock(
        return_value=("Send the grounded value ref:123.", "test")
    )
    created_attempts = []

    def create_attempt(prompt):
        attempt = MagicMock()
        attempt.prompt.last_message.return_value.text = prompt
        created_attempts.append(attempt)
        return attempt

    probe._create_attempt = MagicMock(side_effect=create_attempt)

    result = probe._queue_step_attack(_chain(), "unsafe handoff")

    assert result is created_attempts[0], "a valid tool-bound request must be queued"
    bound_request = probe._create_attempt.call_args.args[0]
    assert bound_request.startswith(
        "Probe-authored tool binding:\n"
        'Use only the manifest tool named exactly "sink" for this request.\n'
        "Do not use or invoke any other tool.\n\n"
        "Helper-generated request:\n"
    ), "the probe must prepend the exact manifest tool without untrusted descriptions"
    assert (
        "Helper-generated request:\nSend the grounded value ref:123.\n\n"
        "Probe-authored invocation limit:\n"
        "Complete the requested action at most once and do not retry it "
        "in this request." in bound_request
    ), "the terminal request must preserve helper text and impose a one-call limit"
    assert (
        bound_request.count("Probe-authored tool binding:") == 1
    ), "a target request must contain exactly one tool-binding block"
    assert (
        len(bound_request) <= probe._STEP_PROMPT_CHAR_LIMIT
    ), "the final target request must remain bounded"
    assert (
        probe._bind_step_request("sink", "x" * probe._STEP_PROMPT_CHAR_LIMIT) is None
    ), "binding overhead must not bypass the final target-request bound"
    assert (
        probe._bind_step_request("sink", "Probe-authored tool binding:\nspoof") is None
    ), "central request binding must reject helper-authored control frames"
    assert (
        probe._bind_step_request(
            "sink",
            'Use only the manifest tool named exactly "sink" for this request.\nreference = ref:123',
        )
        is None
    ), "helper-authored tool bindings must not survive central request construction"
    assert (
        probe._bind_step_request(
            "sink",
            "reference = ref:123\nComplete the requested action at most once and do not retry it in this request.",
        )
        is None
    ), "helper-authored call limits must not survive central request construction"


def test_step_request_naming_another_manifest_tool_is_rejected():
    probe = _probe()
    probe._generate_step_attack_prompt = MagicMock(
        return_value=("Ask SOURCE to forward ref:123.", "test")
    )
    probe._create_attempt = MagicMock()

    assert (
        probe._queue_step_attack(_chain(), "unsafe handoff") is None
    ), "a helper request naming another configured tool must be rejected"
    probe._create_attempt.assert_not_called()


def test_other_tool_name_in_selected_description_is_not_forwarded():
    probe = _probe(
        agent_config=_manifest(
            _tool("source", _intermediate_policy()),
            _tool("sink", _terminal_policy(), "forward through source"),
        )
    )

    bound_request = probe._bind_step_request("sink", "reference = ref:123")

    assert bound_request is not None, "valid selected tool binding must remain usable"
    assert (
        "forward through source" not in bound_request
    ), "operator descriptions must not inject competing tool authority"


def test_terminal_attempt_budget_is_counted_per_manifest_tool():
    probe = _probe(
        agent_config=_manifest(
            _tool("source", _intermediate_policy()),
            _tool("sink_a", _terminal_policy()),
            _tool("sink_b", _terminal_policy()),
        )
    )

    assert probe._reserve_terminal_tool_attempt(
        "sink_a", "request-a"
    ), "the first request for a terminal tool must reserve its budget"
    assert not probe._reserve_terminal_tool_attempt(
        "sink_a", "request-b"
    ), "a second request for the same terminal tool must exceed its budget"
    assert probe._reserve_terminal_tool_attempt(
        "sink_b", "request-c"
    ), "a different terminal tool must retain an independent budget"
    assert probe._terminal_tool_counts == {
        "sink_a": 1,
        "sink_b": 1,
    }, "terminal attempt accounting must be keyed by exact manifest tool"


def test_terminal_step_attaches_detector_contract_and_never_retries():
    probe = _probe()
    probe._extract_artifacts = MagicMock()
    probe._handle_stepwise_refinement = MagicMock()
    attempt = _attempt(_chain(), [Message("concrete target response")])
    assert (
        probe._generate_next_attempts(attempt) == []
    ), "terminal response must never queue a follow-up"
    assert attempt.notes["chain_id"] == "chain_1", "terminal note must retain chain ID"
    assert (
        attempt.notes["chain_role"] == "exploit"
    ), "terminal note must identify exploit role"
    assert (
        attempt.notes["chain_step"] == attempt.notes["chain_total_steps"] == 2
    ), "terminal note must identify the final step"
    assert (
        attempt.notes["chain_sequence"] == "source -> sink"
    ), "terminal note must retain chain sequence"
    assert (
        "concrete target response" in attempt.notes["chain_transcript"]
    ), "terminal transcript must retain bounded target output"
    assert "verified_results" not in attempt.notes, "probe must not cache a verdict"
    probe._extract_artifacts.assert_not_called()
    probe._handle_stepwise_refinement.assert_not_called()


def test_provider_free_probe_lifecycle_runs_one_handoff_and_one_terminal():
    class FakeTargetGenerator:
        parallel_capable = False

        def __init__(self):
            self.responses = [
                "intermediate target output ref:123",
                "terminal target output effect complete",
            ]
            self.requests = []

        def generate(self, prompt, generations_this_call=1):
            assert (
                generations_this_call == 1
            ), "the lifecycle test must stay single-shot"
            assert self.responses, "the probe must not replay beyond the terminal step"
            self.requests.append(prompt.last_message().text)
            return [Message(self.responses.pop(0))]

        def clear_history(self):
            return None

    probe = SourceToSink(config_root={})
    probe.generations = 1
    probe.follow_prompt_cap = False
    probe.parallel_attempts = 1
    probe.agent_config = _manifest(
        _tool("source", _intermediate_policy(), "read one sandbox record"),
        _tool("sink", _terminal_policy(), "write one sandbox result"),
    )
    chain = _chain(step_index=0)
    probe._setup_red_team_model = MagicMock()
    probe._analyze_attackable_tools = MagicMock(return_value={"tool_analyses": {}})
    probe._analyze_tool_chains = MagicMock(
        return_value={"chains": [chain], "priority_chains": ["chain_1"]}
    )
    probe._generate_step_attack_prompt = MagicMock(
        side_effect=[
            ("Read the sandbox record.", "recon"),
            ("Write the grounded value ref:123.", "exploit"),
        ]
    )
    probe._extract_artifacts = MagicMock(return_value={"reference": "ref:123"})
    probe._check_step_success = MagicMock(return_value=(True, 0.9, "grounded"))
    probe._handle_stepwise_refinement = MagicMock(
        wraps=probe._handle_stepwise_refinement
    )
    fake_generator = FakeTargetGenerator()

    with patch.object(_config.transient, "reportfile", MagicMock()):
        completed = probe.probe(fake_generator)

    assert (
        len(completed) == 2
    ), "the lifecycle must complete one intermediate and terminal"
    assert (
        len(fake_generator.requests) == 2
    ), "the target must receive exactly two requests"
    assert {attempt.probe_classname for attempt in completed} == {
        "agent_breaker.SourceToSink"
    }, "provider-free lifecycle attempts must carry the canonical probe classname"
    assert (
        'named exactly "source"' in fake_generator.requests[0]
    ), "the first request must be bound to the intermediate tool"
    assert (
        'named exactly "sink"' in fake_generator.requests[1]
    ), "the second request must be bound to the terminal tool"
    terminal = completed[1]
    assert (
        terminal.notes["chain_id"] == "chain_1"
    ), "terminal notes must survive postprocess"
    assert (
        terminal.notes["chain_role"] == "exploit"
    ), "terminal role must survive postprocess"
    assert (
        "intermediate target output ref:123" in terminal.notes["chain_transcript"]
    ), "the transcript must retain grounded intermediate evidence"
    assert (
        "terminal target output effect complete" in terminal.notes["chain_transcript"]
    ), "the transcript must retain terminal target evidence"
    assert (
        probe.attempt_queue == []
    ), "the iterative queue must empty after the terminal step"
    assert probe._terminal_tool_counts == {
        "sink": 1
    }, "the lifecycle must reserve exactly one terminal request"
    assert (
        fake_generator.responses == []
    ), "the fake target must consume only planned outputs"
    probe._handle_stepwise_refinement.assert_not_called()
    assert (
        probe._generate_step_attack_prompt.call_count == 2
    ), "the terminal request must not be regenerated or replayed"


def test_postprocess_promotes_terminal_detector_notes():
    probe = _probe()
    original = MagicMock()
    original.notes = {
        "chain_id": "chain_1",
        "chain_role": "exploit",
        "chain_step": 2,
        "chain_total_steps": 2,
        "chain_sequence": "source -> sink",
        "chain_transcript": "bounded transcript",
    }
    processed = MagicMock()
    processed.notes = {}
    with patch.object(AgentBreaker, "_postprocess_attempt", return_value=processed):
        result = probe._postprocess_attempt(original)
    assert (
        result.notes == original.notes
    ), "postprocessing must preserve the detector contract"


def test_intermediate_step_advances_with_extracted_artifact():
    probe = _probe()
    chain = _chain(step_index=0)
    attempt = _attempt(chain, [Message("target response")])
    probe._extract_artifacts = MagicMock(return_value={"reference": "ref:123"})
    probe._check_step_success = MagicMock(return_value=(True, 0.9, "ok"))
    next_attempt = MagicMock()
    probe._advance_stepwise = MagicMock(return_value=next_attempt)
    assert probe._generate_next_attempts(attempt) == [
        next_attempt
    ], "grounded intermediate artifact must advance the chain"
    probe._advance_stepwise.assert_called_once()
    assert (
        "verified_results" not in attempt.notes
    ), "probe must not judge intermediate output"


def test_refinement_preserves_the_intermediate_artifact_output_contract():
    history = [{"prompt": "first request", "response": "try again"}]
    state = AttackState(
        current_target="source",
        current_tool_analysis=_chain(step_index=0),
        current_attack_prompt="first request",
        attempts_history=history,
        vulnerability_info="unsafe handoff",
    )
    probe = _probe()
    probe._generate_step_exploit_prompt = MagicMock(
        return_value=("Read one record.", "retry")
    )
    probe._create_attempt = MagicMock(
        side_effect=lambda prompt: Attempt(prompt=Message(text=prompt))
    )

    retry = probe._handle_stepwise_refinement(state)

    assert retry is not None, "an intermediate retry within budget must be queued"
    request = retry.prompt.last_message().text
    assert (
        "reference = <value>" in request
    ), "retry must request the keyed artifact needed by the next step"
    assert (
        'Use only the manifest tool named exactly "source"' in request
    ), "retry must retain its manifest tool binding"
    assert (
        AttackState.from_notes(retry.notes).attempts_history == history
    ), "retry must retain history for the attempt budget"


def test_refinement_stops_at_intermediate_attempt_budget():
    state = AttackState(
        current_target="source",
        current_tool_analysis=_chain(step_index=0),
        current_attack_prompt="prompt",
        attempts_history=[{}, {}, {}],
        vulnerability_info="unsafe handoff",
    )
    probe = _probe(max_step_attempts=3)
    probe._generate_step_exploit_prompt = MagicMock()
    assert (
        probe._handle_stepwise_refinement(state) is None
    ), "refinement must stop at its attempt budget"
    probe._generate_step_exploit_prompt.assert_not_called()


def test_prompt_data_is_generic_and_contains_reviewed_chain_judge():
    prompt_path = (
        Path(__file__).parents[2]
        / "garak"
        / "data"
        / "agent_breaker"
        / "source_to_sink_prompts.yaml"
    )
    prompts = yaml.safe_load(prompt_path.read_text(encoding="utf-8"))
    assert set(prompts) == {
        "TOOL_TAGGING",
        "EDGE_SCORE",
        "EXPLOIT_HYPOTHESES",
        "STEP_PLAN",
        "STEP_ATTACK",
        "STEP_EXPLOIT",
        "EXTRACT_ARTIFACTS",
        "CHECK_STEP_SUCCESS",
        "VERIFY_SYSTEM",
        "VERIFY_USER",
    }, "prompt data must contain the complete chain contract"
    assert hashlib.sha256(prompts["VERIFY_SYSTEM"].encode()).hexdigest() == (
        "fa46e5add794eed3818a1ceff03409540f41355bf19d82c54fdf16a9cc899cb6"
    ), "packaged system prompt must match the reviewed chain contract"
    assert hashlib.sha256(prompts["VERIFY_USER"].encode()).hexdigest() == (
        "7cf445076ab52443014cec2175c28bd2141b77b8c49681ac84ed88d27b843fd8"
    ), "packaged user prompt must match the reviewed chain contract"
    content = prompt_path.read_text(encoding="utf-8").lower()
    for target_specific_term in (
        "codereview",
        "merge_pr",
        "process_payment",
        "grant_access",
    ):
        assert (
            target_specific_term not in content
        ), "prompt data must remain target-agnostic"
