from __future__ import annotations

import json
import logging
from pathlib import Path

import yaml

from jsonlogalert.exceptions import LogAlertConfigError

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

    try:
        if config_path.is_file() and config_path.stat().st_size:
            logging.debug(f"Reading {config_path}")
            with config_path.open() as fp:
                config = json.load(fp) if config_path.suffix == ".json" else yaml.safe_load(fp.read())

    except (OSError, json.JSONDecodeError, yaml.YAMLError) as err:
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
