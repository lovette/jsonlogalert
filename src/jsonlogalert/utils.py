from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from jsonlogalert.exceptions import LogAlertConfigError

if TYPE_CHECKING:
    from io import TextIOWrapper

######################################################################
# UniqueKeyLoader


# Thanks to the conversation at:
# https://gist.github.com/pypt/94d747fe5180851196eb


class UniqueKeyLoader(yaml.SafeLoader):
    """Load YAML and fail if key is duplicated."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict:
        """Internal mapping function.

        Args:
            node (yaml.MappingNode): ??
            deep (bool): ??

        Raises:
            ValueError: Duplicate key found.

        Returns:
            dict
        """
        mapping = set()

        for key_node, _value_node in node.value:
            if ":merge" not in key_node.tag:
                key = self.construct_object(key_node, deep=deep)
                if key in mapping:
                    raise ValueError(f"{key!r}: Duplicate key found in YAML.")
                mapping.add(key)

        return super().construct_mapping(node, deep)


######################################################################
# Helper functions


def read_config_file(config_path: Path) -> dict | None:
    """Open and parse a JSON or YAML configuration file.

    Args:
        config_path (Path): Config file path.

    Raises:
        LogAlertConfigError: Failed to open or parse file.

    Returns:
        dict or None if file does not exist or is empty.
    """
    config = None

    def _read_json_config(fp: TextIOWrapper) -> None:
        try:
            return json.load(fp)
        except json.JSONDecodeError as err:
            raise LogAlertConfigError(f"{err}") from err

    def _read_yaml_config(fp: TextIOWrapper) -> None:
        try:
            return yaml.load(fp.read(), Loader=UniqueKeyLoader)  # noqa: S506
        except (yaml.YAMLError, ValueError) as err:
            raise LogAlertConfigError(f"{err}") from err

    try:
        if config_path.is_file() and config_path.stat().st_size:
            logging.debug(f"Reading {config_path}")
            with config_path.open() as fp:
                config = _read_json_config(fp) if config_path.suffix == ".json" else _read_yaml_config(fp)

    except OSError as err:
        raise LogAlertConfigError(f"{err}") from err

    return config


def resolve_rel_path(name_or_path: str | Path, rel_to_dir: Path | None = None) -> Path:
    """Resolve the path to a file given a file name and directory.

    Args:
        name_or_path (str | Path): Full path, relative path or just a file name.
        rel_to_dir (Path | None, optional): Directory 'name_or_path' may be relative to. Defaults to None.

    Returns:
        Path
    """
    if not isinstance(name_or_path, Path):
        name_or_path = Path(name_or_path)

    if not name_or_path.is_absolute() and rel_to_dir:
        name_or_path = rel_to_dir / name_or_path

    return name_or_path.resolve() if ".." in name_or_path.parts else name_or_path
