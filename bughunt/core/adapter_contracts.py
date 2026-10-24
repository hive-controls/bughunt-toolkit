"""Artifact and side-effect contracts shared by catalog and typed pipelines."""

_INPUTS = {
    ("exchange", "import-raw"): {"url": "urls"},
    ("exchange", "group"): {"exchange_ids": "exchanges"},
    ("exchange", "candidates"): {"exchange_ids": "exchanges"},
    ("exchange", "flow"): {"exchange_ids": "exchanges"},
    ("discover", "default"): {"exchange_id": "exchanges"},
    ("silk", "default"): {"url": "urls"},
    ("forms", "default"): {"url": "urls"},
    ("pulse", "default"): {"urls": "urls"},
    ("redirect", "default"): {"url": "urls"},
    ("vhost", "default"): {"url": "urls"},
    ("decode", "default"): {"target": "urls"},
    ("race", "run"): {"exchange_id": "exchanges"},
    ("zap", "active"): {"exchange_id": "exchanges"},
    ("zap", "export"): {"exchange_ids": "exchanges"},
    ("ct", "default"): {"domain": "hosts"},
    ("tcurl", "default"): {"url": "urls"},
    ("skiff", "default"): {"url": "urls"},
}
_OUTPUTS = {
    "scan": {"observations", "urls", "effect"},
    "silk": {"observations", "urls"},
    "dns": {"dns"},
    "cert": {"tls"},
    "robots": {"urls"},
    "whois": {"observations"},
    "mail": {"observations"},
    "vhost": {"observations"},
    "redirect": {"observations"},
    "repeater": {"observations", "effect"},
    "replay": {"observations"},
    "discover": {"observations"},
    "idor": {"observations"},
    "forms": {"observations", "effect"},
    "diff": {"observations"},
    "jwt": {"inventory"},
    "decode": {"document", "inventory"},
    "roost": {"inventory"},
    "ledger": {"inventory"},
    "policy": {"inventory"},
    "pulse": {"external", "urls", "runs"},
    "ct": {"external", "hosts", "urls", "runs"},
    "carve": {"external", "urls", "runs"},
    "phish": {"external", "document", "effect", "runs"},
    "ioc": {"external", "effect", "runs"},
    "chroma": {"external", "document", "effect", "runs"},
    "urlscan": {"external", "document", "effect", "runs"},
    "tcurl": {"external", "document", "runs"},
    "skiff": {"external", "runs"},
    "oast": {"observations"},
}
_LOCAL = {
    "scope",
    "policy",
    "identity",
    "session",
    "ledger",
    "roost",
    "clutch",
    "blaze",
    "quill",
    "jwt",
    "exchange",
}
_READS = {
    "list",
    "show",
    "status",
    "path",
    "urls",
    "allow",
    "example",
    "validate",
    "check",
}


def input_kinds(name, operation):
    return dict(_INPUTS.get((name, operation), {}))


_OUTPUT_OVERRIDES = {
    ("policy", "import"): {"inventory", "effect"},
    ("ledger", "cleanup"): {"inventory", "effect"},
    ("oast", "show"): {"inventory"},
    ("desync", "status"): {"observations"},
    ("zap", "status"): {"observations"},
    ("snare", "capture"): {"observations", "exchanges"},
    ("snare", "stop"): {"inventory", "effect"},
}


def output_kinds(name, operation):
    if (name, operation) in _OUTPUT_OVERRIDES:
        return set(_OUTPUT_OVERRIDES[name, operation])
    if name in _OUTPUTS:
        return set(_OUTPUTS[name])
    if name == "scope":
        return (
            {"urls"}
            if operation in {"urls", "import-urls"}
            else {"inventory"}
            if operation in _READS
            else {"effect"}
        )
    if name in {"identity", "session", "blaze", "quill", "route"}:
        if name == "identity" and operation == "companion":
            return {"inventory", "effect"}
        return {"inventory"} if operation in _READS else {"effect"}
    if name == "verify":
        return (
            {"runs"}
            if operation == "check"
            else {"effect"}
            if operation == "configure"
            else {"inventory"}
        )
    if name == "clutch":
        return {"document"} if operation == "show" else {"inventory"}
    if name == "exchange":
        return {"exchanges"} if operation.startswith("import-") else {"inventory"}
    if name == "engine":
        return (
            {"observations"}
            if operation in {"start", "dry-run"}
            else {"inventory", "observations"}
            if operation == "doctor"
            else {"inventory"}
        )
    if name in {"race", "desync", "ws", "zap"}:
        return (
            {"effect"}
            if operation == "cancel"
            else {"inventory"}
            if operation in {"status", "show"}
            else {"observations"}
        )
    if name == "snare":
        return (
            {"exchanges", "job"}
            if operation == "default"
            else {"inventory"}
            if operation == "status"
            else {"effect"}
        )
    raise ValueError("Module has no artifact contract")


def side_effect(name, operation):
    if operation == "repl":
        return "interactive"
    if name in _LOCAL:
        if name in {"roost", "jwt", "clutch"} or operation in _READS:
            return "read"
        return "write"
    if operation in {"cancel", "stop", "configure", "init", "download"}:
        return "write"
    if name in {"verify", "engine", "zap", "desync", "ws", "snare"} and operation in {
        "list",
        "map",
        "show",
        "status",
    }:
        return "read"
    if name in {"decode", "diff", "robots", "route", "carve"} or operation == "doctor":
        return "conditional"
    return "network"


def equivalent(name, operation):
    if name == "chroma" and operation == "repl":
        return (
            "Use explicit hunt, url, host, hash, recent, payloads, tag, family, "
            "iocs, fox, bazaar, feodo, sslbl, watch or download operations"
        )
    if name == "repeater":
        return "Provide request and explicit edits; interactive editor is unavailable"
    if name == "snare" and operation == "default":
        return "Provide finite seconds and max_exchanges capture limits"
    if operation == "watch":
        return "Provide a finite polls bound"
    return "run_module with explicit catalog options"
