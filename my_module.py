import json

def function_name(prompt: str) -> list[str]:

    json_string = '{"test_key": "test_value", "test_key_2": [1, 2, 3]}'
    json.loads(json_string) # check that the string is valid json

    return [json_string]