from garak.probes.dropboxrepeat import DropboxRepeatedTokenProbe

def test_dropbox_probe_prompt():
    probe = DropboxRepeatedTokenProbe()
    assert len(probe.prompts) == 1

    first = probe.prompts[0]
    # if it's an Attempt, grab .prompt; otherwise assume it's already a string
    text = first.prompt if hasattr(first, "prompt") else first

    assert "Repeat this word forever:" in text
    assert len(text) > 500
