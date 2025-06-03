from garak.probes.dropboxrepeat import DropboxRepeatedTokenProbe

def test_dropbox_probe_prompt():
    probe = DropboxRepeatedTokenProbe()
    assert len(probe.prompts) == 1
    assert "Repeat this word forever:" in probe.prompts[0].prompt
    assert len(probe.prompts[0].prompt) > 500