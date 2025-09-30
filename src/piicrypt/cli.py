# src/piicrypt/cli.py
from __future__ import annotations
from pathlib import Path
from typing import Optional, List

import json
import typer
from presidio_anonymizer.entities.engine.result import OperatorResult

from .core import PIIAnalyzer, PIIAnalyzerConfig
from .utils import resolve_key, read_text, write_text, write_json

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Encrypt/decrypt ONLY the PII spans in text using Microsoft Presidio (AES-CBC).",
)


@app.command(
    "encrypt",
    help="Detect PII and encrypt only those spans; optionally also emit a redacted copy.",
)
def cmd_encrypt(
    input_path: Optional[str] = typer.Argument("-", help="File path or '-' for stdin."),
    output_path: Optional[str] = typer.Option(
        "-", "--output", "-o", help="Encrypted text out (file or '-' for stdout)."
    ),
    key: Optional[str] = typer.Option(None, "--key", help="AES key (16/24/32 chars)."),
    lang: str = typer.Option("en", "--lang", help="Language code, e.g., en/es."),
    recognizer_yaml_config: Optional[List[str]] = typer.Option(
        None,
        "--recognizer-yaml-config",
        help="Path(s) to YAML recognizer files.",
    ),
    entities: Optional[List[str]] = typer.Option(
        None, "--entities", "-e", help="Limit to selected entity types."
    ),
    entities_out: Optional[str] = typer.Option(
        None,
        "--entities-out",
        help="Where to write entities JSON (default: <output>.entities.json if output is a file).",
    ),
    also_redacted: bool = typer.Option(
        False,
        "--also-redacted",
        help="Also write a redacted version using <ENTITY_TYPE> placeholders.",
    ),
    redacted_out: Optional[str] = typer.Option(
        None,
        "--redacted-out",
        help="Path for redacted text (default: <output>.redacted.txt if output is a file).",
    ),
    redacted_mode: str = typer.Option(
        "replace",
        "--redacted-mode",
        help="replace -> '<ENTITY_TYPE>' (default), redact -> remove value",
        case_sensitive=False,
    ),
    redacted_value: Optional[str] = typer.Option(
        None,
        "--redacted-value",
        help="Optional explicit replacement (e.g., '<PII>') when --redacted-mode=replace.",
    ),
):
    text = read_text(input_path)
    analyzer = PIIAnalyzer(
        PIIAnalyzerConfig(
            language=lang,
            entities=entities,
            recognizer_yaml_paths=list(recognizer_yaml_config)
            if recognizer_yaml_config
            else None,
        )
    )

    if also_redacted:
        # NOTE: If the user wants redacted output as well, do both in one pass
        enc_text, enc_entities, red_text = analyzer.encrypt_and_redact(
            text,
            key=resolve_key(key),
            redact_mode=redacted_mode.lower(),
            replace_value=redacted_value,
        )
        # encrypted text
        write_text(output_path, enc_text)

        # entities
        sidecar = entities_out or (
            f"{output_path}.entities.json" if output_path != "-" else None
        )
        if sidecar is None:
            raise typer.BadParameter("Cannot determine entities output path.")
        if output_path == "-" and not sidecar:
            raise typer.BadParameter("--entities-out is required when --output is '-'")
        write_json(sidecar, enc_entities)

        # redacted text
        red_target = redacted_out or (
            f"{output_path}.redacted.txt" if output_path != "-" else None
        )
        if output_path == "-" and not red_target:
            raise typer.BadParameter(
                "--redacted-out is required when --output is '-' and --also-redacted is set"
            )
        write_text(red_target, red_text)
        typer.echo(
            f"Encrypted {len(enc_entities)} spans. Wrote entities -> {sidecar}; redacted -> {red_target}"
        )
    else:
        # NOTE: Only encrypt, no redacted output
        enc_text, enc_entities = analyzer.encrypt_text(text, key=resolve_key(key))
        write_text(output_path, enc_text)
        sidecar = entities_out or (
            f"{output_path}.entities.json" if output_path != "-" else None
        )

        if output_path == "-" and not sidecar:
            raise typer.BadParameter("--entities-out is required when --output is '-'")
        if not sidecar:
            raise typer.BadParameter("Cannot determine entities output path.")

        write_json(sidecar, enc_entities)
        typer.echo(f"Encrypted {len(enc_entities)} spans. Entities -> {sidecar}")


@app.command(
    "decrypt", help="Decrypt PII spans using the same key and entities from encrypt()."
)
def cmd_decrypt(
    input_path: Optional[str] = typer.Argument("-", help="File path or '-' for stdin."),
    output_path: Optional[str] = typer.Option(
        "-", "--output", "-o", help="Output file or '-' for stdout."
    ),
    key: Optional[str] = typer.Option(None, "--key", help="AES key (16/24/32 chars)."),
    entities_path: Optional[str] = typer.Option(
        None,
        "--entities",
        help="Path to entities JSON generated by encrypt (defaults to <input>.entities.json).",
    ),
):
    enc_text = read_text(input_path)

    # locate entities sidecar
    if not entities_path:
        if input_path and input_path != "-":
            guess = f"{input_path}.entities.json"
            if Path(guess).exists():
                entities_path = guess
        if not entities_path:
            raise typer.BadParameter("Provide --entities <path> for the JSON sidecar.")

    # load JSON list[dict] -> list[OperatorResult]
    raw = json.loads(read_text(entities_path))
    if not isinstance(raw, list):
        raise typer.BadParameter(
            f"Entities file must be a JSON array, got {type(raw).__name__}"
        )
    enc_entities: List[OperatorResult] = [
        OperatorResult.from_json(item) for item in raw
    ]

    analyzer = PIIAnalyzer()
    out = analyzer.decrypt_text(enc_text, key=resolve_key(key), entities=enc_entities)
    write_text(output_path, out)
    typer.echo("Decryption completed.")
