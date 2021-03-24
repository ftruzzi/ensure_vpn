from typing import Generator


def get_dict_values(key, d) -> Generator:
    """
    Returns all values for "key" in nested dict
    """
    if not d:
        return None
    if hasattr(d, "items"):
        for k, v in d.items():
            if k == key:
                yield v
            if isinstance(v, dict):
                for result in get_dict_values(key, v):
                    yield result
            elif isinstance(v, list):
                for d in v:
                    for result in get_dict_values(key, d):
                        yield result
