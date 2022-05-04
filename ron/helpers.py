import os
import uuid
import base64
import re

import yaml

from ron import __version__


def generate_random_cdk_like_suffix():
    return uuid.uuid4().hex[:5].upper()


def to_alpha_numeric(name: str):
    return re.sub(r"[^\w{}]", "", name)


def get_hash(name: str):
    return re.sub(r"\W", "", base64.b64encode(name.encode("utf-8")).decode("utf-8"))


def get_root():
    name = "requirements.txt"
    curr = os.getcwd()
    while True:
        file_list = os.listdir(curr)
        parent_dir = os.path.dirname(curr)
        if name in file_list:
            break
        else:
            if curr == parent_dir:
                break
            else:
                curr = parent_dir
    return curr


def read_ron_config(ron_config_path: str = None):
    ron_configs = []
    base_project_path = get_root()

    if ron_config_path:
        ron_configs.append(ron_config_path)
    else:

        ron_configs.extend(
            os.listdir(os.path.join(str(base_project_path), "deploy/config"))
        )

    if not ron_configs:
        return None

    available_configs = []

    for config in ron_configs:
        full_config_path = os.path.join(
            str(base_project_path), f"deploy/config/{config}"
        )
        with open(full_config_path, "r") as file:
            delivery_content = file.read()
            load_env = yaml.load(delivery_content, Loader=yaml.FullLoader)
            if not load_env:
                return None
            available_configs.append(load_env)

    return available_configs


def write_to_file(template: str, location: str):
    if template:
        dir_path = os.path.join(*location.split("/")[:-1])
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        with open(location, "w") as f:
            f.write(template)
            print(
                f"Successfully applied the changes to: {location} with ron version: {__version__}"
            )
