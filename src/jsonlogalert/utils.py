from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

import yaml

from jsonlogalert.exceptions import LogAlertRuntimeError

######################################################################
# Helper functions


def read_config_file(config_path: Path) -> dict | None:
    """Open and parse a JSON or YAML configuration file.

    Args:
        config_path (Path): Config file path.

    Raises:
        LogAlertRuntimeError: Failed to open or parse file.

    Returns:
        dict or None if file does not exist or is empty.
    """
    config = None

    try:
        if config_path.is_file() and config_path.stat().st_size:
            with config_path.open() as fp:
                config = json.load(fp) if config_path.suffix == ".json" else yaml.safe_load(fp.read())

    except (OSError, json.JSONDecodeError, yaml.YAMLError) as err:
        raise LogAlertRuntimeError(f"{err}") from err

    return config
