# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import wn

import garak._plugins
import garak.probes.base
import garak.probes.topic

# trigger wn config overrides
garak.probes.topic.WordnetBlockedWords()

TEST_LEXICON = "oewn:2023"
TEST_TERM = "abortion"
TEST_SYNSET_ID = "oewn-00231191-n"

wn.download(TEST_LEXICON)
w = wn.Wordnet(TEST_LEXICON)
s = w.synset(TEST_SYNSET_ID)


PROBES = [
    classname
    for (classname, active) in garak._plugins.enumerate_plugins("probes")
    if ".topic.Wordnet" in classname
]


@pytest.mark.parametrize("probename", PROBES)
def test_topic_wordnet_load(probename):
    p = garak._plugins.load_plugin(probename)
    assert isinstance(p, garak.probes.base.Probe)


@pytest.mark.parametrize("probename", PROBES)
def test_topic_wordnet_version(probename):
    p = garak._plugins.load_plugin(probename)
    assert p.lexicon == TEST_LEXICON


@pytest.mark.parametrize("probename", PROBES)
def test_topic_wordnet_get_node_terms(probename):
    p = garak._plugins.load_plugin(probename)
    terms = p._get_node_terms(s)
    assert list(terms) == ["abortion"]


@pytest.mark.parametrize("probename", PROBES)
def test_topic_wordnet_get_node_children(probename):
    p = garak._plugins.load_plugin(probename)
    children = p._get_node_children(s)
    assert children == [wn.synset("oewn-00231342-n"), wn.synset("oewn-00232028-n")]


@pytest.mark.parametrize("probename", PROBES)
def test_topic_wordnet_get_node_id(probename):
    p = garak._plugins.load_plugin(probename)
    assert p._get_node_id(s) == TEST_SYNSET_ID


def test_topic_wordnet_blocklist_get_initial_nodes():
    p = garak.probes.topic.WordnetBlockedWords()
    p.target_topic = TEST_TERM
    initial_nodes = p._get_initial_nodes()
    assert initial_nodes == [
        s,
        wn.synset("oewn-07334252-n"),
        wn.synset("oewn-00231342-n"),
        wn.synset("oewn-00232028-n"),
    ]
