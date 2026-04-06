from typing import List, Dict, Any


def extract_key_types(regex_dict_list: List[Dict[str, Any]]) -> List[str]:
    all_keys = [key for dict in regex_dict_list for key in dict]
    return [key.replace("_", " ").title() for key in all_keys]
