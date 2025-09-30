# src/piicrypt/nlp.py

from __future__ import annotations
from typing import Optional, List
from presidio_analyzer import (
    AnalyzerEngine,
    RecognizerRegistry,
)
from pathlib import Path


def build_analyzer(
    *,
    yaml_paths: Optional[List[str]] = None,
) -> AnalyzerEngine:
    """
    Build an AnalyzerEngine.

    If yaml_paths is provided, load the recognizers from the first YAML file.
    If not, use the default recognizers.
    """
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()  # Load the built-ins

    if yaml_paths:
        for yaml_path in yaml_paths:
            path = Path(yaml_path)
            if not path.is_file():
                raise FileNotFoundError(f"YAML file not found: {yaml_path}")
            registry.add_recognizers_from_yaml(str(path))

    return AnalyzerEngine(registry=registry)
