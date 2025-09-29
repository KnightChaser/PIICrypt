# src/piicahr/core.py

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict, Any

from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine
from presidio_anonymizer.entities import OperatorConfig
from presidio_analyzer import AnalyzerEngine
from .nlp import build_analyzer

_VALID_AES_KEY_LENS = {16, 24, 32}  # in bytes: AES-128, AES-192, AES-256


@dataclass
class PIIAnalyzerConfig:
    language: str = "en"
    entities: Optional[List[str]] = None  # e.g., ["EMAIL_ADDRESS", "PHONE_NUMBER"]
    use_custom: bool = False


class PIIAnalyzer:
    def __init__(self, config: Optional[PIIAnalyzerConfig] = None) -> None:
        self.config = config or PIIAnalyzerConfig()
        self.analyzer: AnalyzerEngine = build_analyzer(
            use_custom=self.config.use_custom
        )
        self.anonymizer: AnonymizerEngine = AnonymizerEngine()
        self.deanonymizer: DeanonymizeEngine = DeanonymizeEngine()

    @staticmethod
    def _check_key(key: str) -> None:
        """
        Check if the provided key is valid for AES encryption.
        """
        if len(key) not in _VALID_AES_KEY_LENS:
            raise ValueError(
                f"Invalid AES key length: {len(key)}. "
                f"Valid lengths are: {_VALID_AES_KEY_LENS}"
            )

    def encrypt_text(self, text: str, *, key: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Detect PII (Personally Identifiable Information) and apply AES-CBC
        encrypt only on those spans. Non-PII remains intact.
        """
        self._check_key(key)
        results = self.analyzer.analyze(
            text=text,
            entities=self.config.entities,
            language=self.config.language,
        )
        operators = {"DEFAULT": OperatorConfig("encrypt", {"key": key})}
        anonymize_results = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,  # type: ignore
            operators=operators,
        )

        # NOTE: Presidio returns JSON-serializable dicts in .items
        serializable_entities = [item.to_dict() for item in anonymize_results.items]
        return (anonymize_results.text, serializable_entities)

    def decrypt_text(
        self, text_with_encrypted_pii: str, *, entities: list, key: str
    ) -> str:
        """
        Reverse the AES-CBC encryption on PII spans using the same key
        that was used for encryption.
        """
        self._check_key(key)
        operators = {"DEFAULT": OperatorConfig("decrypt", {"key": key})}
        return self.deanonymizer.deanonymize(
            text=text_with_encrypted_pii,
            operators=operators,
            entities=entities,
        ).text
