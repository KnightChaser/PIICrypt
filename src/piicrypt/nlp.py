# src/piicrypt/nlp.py

from __future__ import annotations
from typing import Optional
from presidio_analyzer import (
    AnalyzerEngine,
    RecognizerRegistry,
    Pattern,
    PatternRecognizer,
)


def build_analyzer(
    *,
    use_custom: bool = False,
) -> AnalyzerEngine:
    """
    Build an AnalyzerEngine. You can evolve this to a full NlpEngineProvider
    with multiple spaCy models (EN/ES/etc.).
    """
    registry: Optional[RecognizerRegistry] = None

    if use_custom:
        # NOTE: Example custom recognizer (GitHub token)
        ghp = Pattern(name="ghp_token", regex=r"ghp_[A-Za-z0-9]{36}", score=0.6)
        ghp_rec = PatternRecognizer(
            supported_entity="GITHUB_TOKEN",
            patterns=[ghp],
            context=["token", "github", "key"],
        )
        registry = RecognizerRegistry()
        registry.add_recognizer(ghp_rec)

    return AnalyzerEngine(registry=registry) if registry else AnalyzerEngine()
