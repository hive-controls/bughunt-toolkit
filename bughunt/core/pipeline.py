"""Strict, inert declarative plans for bounded sequential module execution."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
from pathlib import Path
import re

from bughunt.core import adapters, exchange, ledger
from bughunt.core.results import safe_url

MAX_PLAN_BYTES = 1_048_576
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_LIMITS = {
    "requests": (int, 100),
    "seconds": ((int, float), 300),
    "concurrency": (int, 1),
    "requests_per_second": ((int, float), math.inf),
    "bytes": (int, 16 * 1024 * 1024),
}
_SECRET_OPTIONS = {
    "cookie",
    "authorization",
    "auth",
    "api_key",
    "token",
    "password",
    "expect_principal",
    "expect_role",
    "body",
    "data",
}


def _closed(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value):
        raise ValueError("Missing pipeline fields")
    if set(value) - set(required) - set(optional):
        raise ValueError("Unknown pipeline fields")


def _bounded(value, depth=0):
    if depth > 20:
        raise ValueError("Pipeline nesting limit")
    if isinstance(value, dict):
        if len(value) > 1000 or any(type(key) is not str for key in value):
            raise ValueError("Pipeline object limit")
        for item in value.values():
            _bounded(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 1000:
            raise ValueError("Pipeline collection limit")
        for item in value:
            _bounded(item, depth + 1)
    elif type(value) is float and not math.isfinite(value):
        raise ValueError("Nonfinite pipeline value")
    elif value is not None and type(value) not in {str, bool, int, float}:
        raise ValueError("Pipeline requires JSON values")


def _limits(value, *, complete):
    _closed(value, _LIMITS if complete else (), () if complete else _LIMITS)
    for key, limit in value.items():
        types, maximum = _LIMITS[key]
        if isinstance(limit, bool) or not isinstance(limit, types):
            raise ValueError("Invalid pipeline limit type")
        if not math.isfinite(limit) or not 0 < limit <= maximum:
            raise ValueError("Pipeline limit outside bounds")
    return dict(value)


def _yaml_events(yaml, raw):
    depth = 0
    try:
        for count, event in enumerate(yaml.parse(raw), 1):
            if (
                count > 10000
                or isinstance(event, yaml.AliasEvent)
                or getattr(event, "tag", None)
            ):
                raise ValueError("YAML aliases, tags or excessive nodes are forbidden")
            if isinstance(event, (yaml.SequenceStartEvent, yaml.MappingStartEvent)):
                depth += 1
            elif isinstance(event, (yaml.SequenceEndEvent, yaml.MappingEndEvent)):
                depth -= 1
            if depth > 20:
                raise ValueError("YAML nesting limit")
    except yaml.YAMLError as error:
        raise ValueError("Invalid pipeline YAML") from error


def _yaml_document(raw):
    try:
        import yaml
    except ImportError as error:
        raise ValueError("YAML requires the pipeline-yaml extra") from error
    _yaml_events(yaml, raw)

    class Loader(yaml.SafeLoader):
        pass

    def mapping(loader, node):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=True)
            if type(key) is not str or key == "<<" or key in result:
                raise ValueError(
                    "YAML mapping keys must be unique strings without merges"
                )
            result[key] = loader.construct_object(value_node, deep=True)
        return result

    Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        return yaml.load(raw, Loader=Loader)
    except yaml.YAMLError as error:
        raise ValueError("Invalid pipeline YAML") from error


def _read_document(source):
    if isinstance(source, dict):
        _bounded(source)
        raw = exchange.canonical(source)
        if len(raw) > MAX_PLAN_BYTES:
            raise ValueError("Pipeline document size limit")
        return json.loads(raw)
    path = Path(source)
    if not path.is_file() or path.stat().st_size > MAX_PLAN_BYTES:
        raise ValueError("Missing or oversized pipeline document")
    with path.open("rb") as handle:
        raw = handle.read(MAX_PLAN_BYTES + 1)
    if len(raw) > MAX_PLAN_BYTES:
        raise ValueError("Pipeline document size limit")
    value = (
        _yaml_document(raw)
        if path.suffix.lower() in {".yaml", ".yml"}
        else exchange.load_json(raw)
    )
    _bounded(value)
    return value


def _safe_options(value):
    if not isinstance(value, dict):
        raise ValueError("Pipeline options require an object")
    for name, option in value.items():
        if option and (
            name.lower().replace("-", "_") in _SECRET_OPTIONS
            or re.fullmatch(ledger._CREDENTIAL_NAME, name, re.I)
        ):
            raise ValueError(
                "Use a saved identity instead of inline credentials or bodies"
            )
        values = option if isinstance(option, list) else [option]
        for item in values:
            if isinstance(item, (list, dict)):
                raise ValueError("Nested pipeline options are not supported")
            if isinstance(item, str):
                if _inline_credentials(item):
                    raise ValueError("Inline credential headers are forbidden")
                if item.startswith(("http://", "https://")) and not safe_url(item):
                    raise ValueError("Unsafe pipeline URL")


def _inline_credentials(value):
    from bughunt.core.http import is_credential_header

    if ledger._HEADER.search(value) or ledger._KEY.search(value):
        return True
    for line in value.splitlines():
        name, separator, _content = line.partition(":")
        if separator and is_credential_header(name.strip()):
            return True
    return False


def _output_kinds(step):
    return adapters.output_kinds(step["module"], step["operation"])


def _references(step, previous):
    references = step.get("inputs", {})
    if not isinstance(references, dict):
        raise ValueError("Typed inputs require an object")
    permitted = adapters.input_kinds(step["module"], step["operation"])
    placeholders = {}
    for destination, reference in references.items():
        indices = _selection(reference)
        if (
            destination in step["options"]
            or permitted.get(destination) != reference["artifact"]
        ):
            raise ValueError("Conflicting or incompatible typed input")
        source = previous.get(reference["step"])
        if source is None or reference["artifact"] not in _output_kinds(source):
            raise ValueError("Typed input requires a compatible previous step")
        placeholder = {
            "exchanges": "a" * 64,
            "urls": "https://example.invalid/",
            "hosts": "example.invalid",
        }[reference["artifact"]]
        placeholders[destination] = (
            [placeholder] * len(indices) if "indices" in reference else placeholder
        )
    return placeholders


def _selection(reference):
    _closed(reference, {"step", "artifact"}, {"index", "indices"})
    if any(not isinstance(reference[name], str) for name in ("step", "artifact")):
        raise ValueError("Invalid typed input source")
    if ("index" in reference) == ("indices" in reference):
        raise ValueError("Typed input requires exactly one selection")
    selected = reference.get("indices", [reference.get("index")])
    if not isinstance(selected, list) or not 1 <= len(selected) <= 32:
        raise ValueError("Typed input selection requires 1..32 indices")
    if any(type(index) is not int or not 0 <= index < 1000 for index in selected):
        raise ValueError("Typed input index outside bounds")
    if len(set(selected)) != len(selected):
        raise ValueError("Typed input indices must be unique")
    return selected


def _input_bytes(path):
    absolute = path.absolute()
    if any(
        parent.is_symlink() or parent.is_junction()
        for parent in (absolute, *absolute.parents)
    ):
        raise ValueError("Pipeline inputs cannot traverse links or junctions")
    if not absolute.is_file() or absolute.stat().st_size > MAX_PLAN_BYTES:
        raise ValueError("Missing or oversized pipeline input")
    with absolute.open("rb") as handle:
        raw = handle.read(MAX_PLAN_BYTES + 1)
    if len(raw) > MAX_PLAN_BYTES:
        raise ValueError("Pipeline input size limit")
    return absolute, raw


def _private_files(step, trusted):
    for name in adapters.file_options(step["module"], step["operation"]):
        if name not in step["options"] or step["options"][name] is None:
            continue
        value = step["options"][name]
        if isinstance(value, list):
            step["options"][name] = [
                _private_file(item, f"{step['id']}:{name}:{index}", trusted)
                for index, item in enumerate(value)
            ]
        else:
            step["options"][name] = _private_file(
                value, step["id"] + ":" + name, trusted
            )


def _private_file(value, key, trusted):
    if not isinstance(value, str) or value == "-":
        raise ValueError("Pipeline file input must be a regular file")
    path, raw = _input_bytes(Path(value).expanduser())
    reference = "input-" + exchange.digest(key.encode())
    trusted[reference] = {
        "path": str(path),
        "sha256": exchange.digest(raw),
        "bytes": len(raw),
    }
    return {
        "trusted_input": reference,
        "sha256": trusted[reference]["sha256"],
        "bytes": len(raw),
    }


def _native_limits(module, operation, args):
    constraints = {}
    bounded_jobs = {"discover", "race", "desync", "ws", "zap", "engine", "snare"}
    if module in bounded_jobs:
        for name in ("requests", "seconds"):
            value = getattr(args, name, None)
            if value is not None:
                constraints[name] = value
    if module == "engine" and operation in {"start", "dry-run"}:
        from bughunt.integrations.browser_actor import PROFILE_ID

        defaults = {"zap-owned-active": 40, PROFILE_ID: 20}
        maximum = defaults.get(args.profile_id)
        if maximum is not None:
            constraints["requests"] = (
                args.requests if args.requests is not None else maximum
            )
    if module == "desync" and operation in {"run", "dry-run"}:
        from bughunt.labs.desync import WRITE_CAP

        constraints["requests"] = WRITE_CAP
    if module == "ws" and operation in {"capture", "replay"}:
        constraints["requests"] = 16
    if module == "skiff":
        rate = getattr(args, "rps", None)
        delay = getattr(args, "delay", 0)
        if rate is not None:
            constraints["requests_per_second"] = rate
        if delay:
            if type(delay) not in {int, float} or not math.isfinite(delay) or delay < 0:
                raise ValueError("Invalid native operation delay")
            constraints["requests_per_second"] = min(rate or math.inf, 1 / delay)
    return _limits(constraints, complete=False)


def _step(value, previous, trusted):
    _closed(value, {"id", "module"}, {"operation", "options", "inputs", "limits"})
    if not isinstance(value["id"], str) or not _IDENTIFIER.fullmatch(value["id"]):
        raise ValueError("Invalid pipeline step ID")
    if value["id"] in previous:
        raise ValueError("Duplicate pipeline step ID")
    value["module"] = adapters.canonical_module(value["module"])
    value.setdefault("operation", "default")
    value.setdefault("options", {})
    if not isinstance(value["operation"], str):
        raise ValueError("Invalid pipeline operation")
    value["operation"] = adapters.canonical_operation(
        value["module"], value["operation"]
    )
    _safe_options(value["options"])
    placeholders = _references(value, previous)
    args = adapters.parse_options(
        value["module"], value["operation"], {**value["options"], **placeholders}
    )
    if adapters.pipeline_restriction(value["module"], value["operation"], vars(args)):
        raise ValueError("Operation is not eligible for a pipeline")
    if value["module"] == "verify" and value["operation"] == "configure":
        raise ValueError("Authority configuration is not a pipeline operation")
    if "limits" in value:
        _limits(value["limits"], complete=False)
    for name, maximum in _native_limits(
        value["module"], value["operation"], args
    ).items():
        value.setdefault("limits", {})[name] = min(
            value.get("limits", {}).get(name, maximum), maximum
        )
    _private_files(value, trusted)
    return value


@dataclass(frozen=True)
class PipelinePlan:
    _document: bytes = field(repr=False)
    _trusted_inputs: bytes = field(repr=False)

    @property
    def document(self):
        return json.loads(self._document)

    @property
    def limits(self):
        return self.document["limits"]

    @property
    def trusted_inputs(self):
        return json.loads(self._trusted_inputs)

    @property
    def sha256(self):
        return exchange.digest(self._document)

    def verify_inputs(self):
        for metadata in self.trusted_inputs.values():
            _, raw = _input_bytes(Path(metadata["path"]))
            if (
                exchange.digest(raw) != metadata["sha256"]
                or len(raw) != metadata["bytes"]
            ):
                raise ValueError("Pipeline input changed")


def load_pipeline(source) -> PipelinePlan:
    document = _read_document(source)
    _closed(document, {"schema_version", "mission", "limits", "steps"})
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ValueError("Unsupported pipeline version")
    if not isinstance(document["mission"], str) or not _IDENTIFIER.fullmatch(
        document["mission"]
    ):
        raise ValueError("Invalid pipeline mission")
    limits = _limits(document["limits"], complete=True)
    if not isinstance(document["steps"], list) or not 1 <= len(document["steps"]) <= 32:
        raise ValueError("Pipeline requires 1..32 sequential steps")
    previous, trusted = {}, {}
    for value in document["steps"]:
        step = _step(value, previous, trusted)
        previous[step["id"]] = step
        for name, limit in step.get("limits", {}).items():
            limits[name] = min(limits[name], limit)
    if sum(metadata["bytes"] for metadata in trusted.values()) > MAX_PLAN_BYTES:
        raise ValueError("Pipeline total input size limit")
    document["limits"] = limits
    return PipelinePlan(exchange.canonical(document), exchange.canonical(trusted))


def run_pipeline(source, *, execute=False):
    from bughunt.core.pipeline_runner import run_pipeline as run

    return run(source, execute=execute)


def resume_pipeline(identifier, *, execute=False):
    from bughunt.core.pipeline_runner import resume_pipeline as resume

    return resume(identifier, execute=execute)


def pipeline_schema():
    from bughunt.core.pipeline_cli import pipeline_schema as schema

    return schema()


def cli_result(words):
    from bughunt.core.pipeline_cli import cli_result as dispatch

    return dispatch(words)
