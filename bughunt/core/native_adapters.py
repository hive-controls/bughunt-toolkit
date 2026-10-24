"""Structured adapters around bundled producers; terminal rendering is never parsed."""

from argparse import Namespace
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from bughunt.core import exchange, ledger, workspace
from bughunt.core.results import Artifact, ExecutionContext, ModuleOutput
from bughunt.modules import load_builtin

if TYPE_CHECKING:
    import httpx
    from bughunt.core.report import HostReport
    from bughunt.core.scanner import ScanPlan


def inventory(resource: str, values) -> ModuleOutput:
    items = values if isinstance(values, list) else [values]
    return ModuleOutput(
        [Artifact.create("inventory", {"resource": resource, "items": items})]
    )


def observations(value: dict, *, run_ids: list[str] | None = None) -> ModuleOutput:
    runs = run_ids or ([value["run_id"]] if value.get("run_id") else [])
    artifact = Artifact.create(
        "observations",
        {
            "classification": value.get("classification", "observation"),
            "items": [
                {
                    "kind": "analysis",
                    "subject": value.get("target", "selected-input"),
                    "attributes": value,
                }
            ],
            "source_run_ids": runs,
        },
    )
    status = (
        "partial"
        if value.get("classification") in {"invalid", "inconclusive"}
        else "success"
    )
    return ModuleOutput([artifact], runs, status=status)


def _effect(resource, action, identifiers=(), changed=True):
    return ModuleOutput(
        [
            Artifact.create(
                "effect",
                {
                    "resource": resource,
                    "action": action,
                    "changed": changed,
                    "identifiers": list(identifiers),
                },
            )
        ]
    )


def _scope(operation, args):
    if operation in {"list", "path"}:
        return inventory(
            "scope",
            {
                "entries": workspace.read_entries(),
                "active": workspace.scope_is_active(),
                "url_count": len(workspace.read_urls()),
            },
        )
    if operation == "urls":
        return ModuleOutput([Artifact.create("urls", {"urls": workspace.read_urls()})])
    if operation == "allow":
        permitted = workspace.allowed(args.target)
        result = inventory(
            "scope-decision", {"target": args.target, "permitted": permitted}
        )
        result.status = "success" if permitted else "blocked"
        return result
    if operation == "init":
        existed = workspace.scope_is_active()
        workspace.init_workspace()
        return _effect("scope", operation, changed=not existed)
    if operation in {"add", "remove"}:
        editor = (
            workspace.add_entries if operation == "add" else workspace.remove_entries
        )
        changed, _unchanged = editor(args.hosts)
        return _effect("scope", operation, changed, bool(changed))
    if operation == "import-urls":
        from bughunt.modules.scope import _screen_urls

        if not workspace.scope_is_active():
            raise ValueError("Scope must be initialized")
        values, _skipped = _screen_urls(
            Path(args.file).read_text(encoding="utf-8"), workspace.allowed
        )
        workspace.remember_urls(values)
        return ModuleOutput([Artifact.create("urls", {"urls": values})])
    raise ValueError("Unknown scope operation")


def _policy(operation, args):
    from bughunt.core.policy import read_document
    from bughunt.modules import policy

    if operation == "example":
        return inventory("policy-example", policy.example_document())
    document, profile = read_document(args.file or policy.policy_path())
    if operation == "check":
        decision = profile.decide(
            args.target,
            args.operation,
            method=args.method,
            callback_domain=args.callback_domain,
        )
        result = inventory("policy-decision", asdict(decision))
        result.status = "success" if decision.permitted else "blocked"
        return result
    if operation == "import":
        policy.install_document(document)
    result = inventory("policy", policy._summary(profile))
    result.status = (
        "success"
        if operation == "import" or profile.freshness() == "verified"
        else "blocked"
    )
    if operation == "import":
        result.artifacts.extend(_effect("policy", "import").artifacts)
    return result


def _ledger(operation, args):
    if operation == "list":
        return inventory(
            "ledger",
            [
                ledger.manifest_for(path.parent.name)
                for path in sorted(ledger.runs_dir().glob("*/manifest.json"))
            ],
        )
    if operation == "export":
        return inventory("ledger-export", ledger.export_run(args.run_id))
    manifest = ledger.manifest_for(args.run_id)
    changed = operation == "cleanup" and manifest.get("cleanup") != args.state
    if operation == "cleanup":
        manifest["cleanup"] = args.state
        ledger._write_private(
            ledger.runs_dir() / args.run_id / "manifest.json",
            exchange.canonical(manifest),
        )
    output = inventory("ledger", manifest)
    if operation == "cleanup":
        output.artifacts.extend(
            _effect("ledger-cleanup", args.state, [args.run_id], changed).artifacts
        )
    return output


def _exchange(operation, args):
    from bughunt.core import triage
    from bughunt.modules import exchange as command

    if operation.startswith("import-"):
        identifiers = command._import(args)
        return ModuleOutput(
            [Artifact.create("exchanges", {"exchange_ids": identifiers})]
        )
    if operation == "list":
        return inventory(
            "exchange",
            [
                exchange.summary(exchange.read(path.stem))
                for path in sorted(exchange.directory().glob("*.json"))
            ],
        )
    if operation == "show":
        return inventory("exchange", exchange.summary(exchange.read(args.exchange_id)))
    if operation == "group":
        return inventory(
            "exchange-group",
            triage.response_groups(args.exchange_ids, normalization=args.normalization),
        )
    if operation == "candidates":
        return inventory(
            "exchange-candidates", triage.html_candidates(args.exchange_ids)
        )
    if operation == "flow":
        return inventory("exchange-flow", triage.flow_summary(args.exchange_ids))
    return inventory("exchange-export", command._export(args))


def _engine(operation, args, *, dry_run=False):
    from bughunt.core import engine, job
    from bughunt.console import capability_map
    from bughunt.modules import engine as command

    if operation == "list":
        return inventory("engine-capabilities", engine.capabilities())
    if operation == "map":
        return inventory("engine-map", capability_map.describe())
    if operation == "doctor":
        if not args.probe:
            from bughunt.integrations import burp_intake

            return inventory("engine-doctor", burp_intake.doctor(config=args.config))
        from bughunt.integrations import burp_intake

        if not args.mission or not args.target:
            raise ValueError("Doctor probe requires mission and target")
        plan = burp_intake.prepare(
            mission=args.mission,
            url=args.target,
            method=args.method,
            source_id="doctor-probe",
            seconds=args.seconds,
            config=args.config,
        )
        return observations(burp_intake.run(plan, probe=True))
    if operation in {"start", "dry-run"}:
        plan = command._prepare(args)
        preview = dry_run or operation == "dry-run"
        value = engine.preview(plan) if preview else engine.run(plan)
        output = observations(value)
        if preview:
            output.status = "planned"
        return output
    if operation == "cancel":
        job.cancel(args.job_id)
    return inventory("job", job.status(args.job_id))


def _discover(_operation, args, *, dry_run=False):
    from bughunt.core import discovery

    candidates = [
        (kind, name)
        for kind in ("header", "cookie", "query")
        for name in getattr(args, kind)
    ]
    try:
        record = exchange.read(args.exchange_id)
    except FileNotFoundError as error:
        raise ValueError("Selected capture is missing") from error
    plan = discovery.prepare(
        record,
        candidates,
        maximum=args.requests,
        seconds=args.seconds,
        max_bytes=args.max_bytes,
    )
    preview = dry_run or args.dry_run
    output = observations(
        discovery.preview(plan) if preview else discovery.execute(plan)
    )
    if preview:
        output.status = "planned"
    return output


def _identity(operation, args):
    from bughunt.core import identity

    if operation == "list":
        return inventory(
            "identity",
            {
                "selected": identity.selected_name(),
                "profiles": identity.list_profiles(),
            },
        )
    if operation == "show":
        return inventory("identity", identity.show_profile(args.name))
    if operation == "create":
        identity.create_profile(args.name, args.kind, args.origin, owned=args.owned)
    elif operation == "use":
        identity.use_profile(args.name)
    elif operation == "set":
        if args.prompt or not args.value:
            raise ValueError("Embedding requires an explicit credential value")
        identity.set_credential(args.name, args.header, " ".join(args.value).strip())
    elif operation == "clear":
        identity.clear_profile(args.name)
    elif operation == "companion":
        if args.clear_companions and args.header:
            raise ValueError("Companion names and clear are mutually exclusive")
        if not args.header and not args.clear_companions:
            return inventory(
                "identity-companions",
                {
                    "name": args.name,
                    "companion_headers": identity.show_profile(args.name)[
                        "companion_headers"
                    ],
                },
            )
        identity.set_companion_headers(
            args.name, [] if args.clear_companions else args.header
        )
    else:
        raise ValueError("Unknown identity operation")
    return _effect("identity", operation, [args.name])


def _session(operation, args):
    from bughunt.core import session

    saved = session.load_session()
    if operation == "show":
        return inventory("session", {"saved_headers": sorted(saved)})
    if operation == "set":
        value = " ".join(args.value).strip()
        if not value or session.has_line_separator(value):
            raise ValueError("Invalid session value")
        updated = {**saved, args.kind: value}
    elif operation == "clear":
        updated = {
            key: value
            for key, value in saved.items()
            if args.kind is not None and key != args.kind
        }
    else:
        raise ValueError("Unknown session operation")
    session.write_session(updated)
    return _effect("session", operation, changed=updated != saved)


def _verify(operation, args):
    from bughunt.core import egress, identity, verification
    from bughunt.modules import verify as command

    if operation == "configure":
        if args.prompt_principal or args.prompt_role:
            raise ValueError("Embedding requires explicit verification values")
        principal, role = command._expected_values(args)
        verification.configure(
            args.name,
            args.url,
            args.principal_path,
            principal,
            args.role_path,
            role,
            expected_status=args.status,
            max_bytes=args.max_bytes,
            timeout_seconds=args.timeout,
            ttl_seconds=args.ttl,
            role_contains=args.role_contains,
        )
        return _effect("verification", operation, [args.name])
    if operation == "show":
        return inventory(
            "verification",
            command._public_configuration(
                args.name, verification.read_configuration(args.name)
            ),
        )
    if operation == "status":
        return inventory("verification-readiness", command._status_readiness())
    if operation != "check":
        raise ValueError("Unknown verification operation")
    try:
        if identity.selected_name() != args.name:
            raise verification.VerificationError(
                "Selected actor differs from requested actor"
            )
        with egress.client(operation="manual", follow_redirects=False) as client:
            run_id = verification.verify_selected(client)
    except verification.VerificationError as error:
        raise egress.PolicyBlocked("verification-blocked") from error
    return ModuleOutput([Artifact.create("runs", {"run_ids": [run_id]})], [run_id])


def _simple_local(name, operation, args):
    module = load_builtin(name)
    if name == "roost":
        return inventory("engagement", asdict(module.gather()))
    if name == "jwt":
        token = module._pick_token(args)
        if not token:
            raise ValueError("JWT required")
        header, payload, signed = module.decode_token(token)
        return inventory(
            "jwt-unverified",
            {
                "header": header,
                "claims": payload,
                "signed": signed,
                "signature_verified": False,
                "notes": module.review_notes(header, payload),
            },
        )
    producer = getattr(module, "run_structured", None)
    if producer is None:
        return ModuleOutput(
            status="unsupported",
            errors=[
                {
                    "code": "structured_producer_pending",
                    "message": "Structured producer is not implemented",
                    "retryable": False,
                }
            ],
        )
    return producer(args)


def _clutch(operation, args):
    from bughunt.modules import clutch

    if operation == "list":
        return inventory(
            "requests", [asdict(value) for value in clutch.list_requests()]
        )
    if operation == "show":
        return ModuleOutput(
            [
                Artifact.create(
                    "document",
                    {
                        "media_type": "message/http",
                        "text": clutch.request_text(args.name),
                        "truncated": False,
                    },
                )
            ]
        )
    raise ValueError("Unknown saved request operation")


def _blaze(operation, args):
    from bughunt.modules import blaze

    if operation == "list":
        label = blaze._require_label(args.label) if args.label else None
        return inventory(
            "marks",
            [
                {"label": owner, "url": target}
                for owner, target in blaze.read_marks()
                if label is None or owner == label
            ],
        )
    if operation == "add":
        label, target, changed = blaze.add_mark(args.label, args.url)
        return _effect("marks", operation, [label, target], changed)
    if operation == "remove":
        label, target = blaze.remove_mark(args.label, args.url)
        return _effect("marks", operation, [label, target])
    raise ValueError("Unknown marks operation")


def _quill(operation, args):
    from bughunt.modules import quill

    if operation == "list":
        return inventory(
            "notes",
            [{"timestamp": stamp, "text": text} for stamp, text in quill.read_notes()],
        )
    if operation == "add":
        stamp, _ = quill.append_note(args.text)
        return _effect("notes", operation, [stamp])
    if operation == "clear":
        return _effect("notes", operation, changed=quill.clear_notes())
    raise ValueError("Unknown notes operation")


def _dns(_operation, args, *, dry_run=False):
    from bughunt.modules import dns

    name, resolver = dns._vet(args)
    if dry_run:
        output = inventory(
            "dns-plan",
            {
                "name": name,
                "resolver": resolver,
                "port": args.port,
                "planned_queries": len(dns.RECORD_TYPES),
                "maximum_queries_with_retries": 2 * len(dns.RECORD_TYPES),
                "outbound_actions": 0,
            },
        )
        output.status = "planned"
        return output
    records, notes, failed = dns.lookup_records(name, resolver, args.port, args.timeout)
    artifact = Artifact.create(
        "dns",
        {
            "name": name,
            "resolver": resolver,
            "records": [
                {
                    "name": record.name,
                    "type": dns._LABEL_OF_CODE[record.rtype],
                    "ttl": record.ttl,
                    "value": record.text,
                }
                for record in records
            ],
            "errors": ["dns_response_error"] if failed else [],
        },
    )
    return ModuleOutput(
        [artifact], status="partial" if failed or notes else "success", warnings=notes
    )


def _cert(_operation, args, *, dry_run=False):
    from bughunt.modules import cert

    host, port = cert._vet(args)
    if dry_run:
        output = inventory(
            "certificate-plan",
            {
                "host": host,
                "port": port,
                "planned_connections": 1,
                "outbound_actions": 0,
                "verifies_certificate": False,
            },
        )
        output.status = "planned"
        return output
    certificate = cert.parse_certificate(
        cert.fetch_certificate(host, port, args.timeout)
    )
    artifact = Artifact.create(
        "tls",
        {
            "host": host,
            "port": port,
            "subject": {"text": certificate.subject},
            "issuer": {"text": certificate.issuer},
            "dns_names": [
                name[4:] for name in certificate.names if name.startswith("DNS:")
            ],
            "ip_names": [
                name[3:] for name in certificate.names if name.startswith("IP:")
            ],
            "not_before": certificate.not_before,
            "not_after": certificate.not_after,
        },
    )
    return ModuleOutput(
        [artifact],
        warnings=["Presented certificate was read without trust verification"],
    )


def _robots(_operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.core import pagefetch
    from bughunt.modules import robots

    try:
        if dry_run:
            base, _scoped = robots._screen_arguments(args)
            if not args.fetch:
                robots._from_files(args.inputs, base)
            return _planned(
                "robots-plan",
                {
                    "fetch": args.fetch,
                    "input_count": len(args.inputs),
                    "outbound_actions": 0,
                },
            )
        value = robots.collect(args, capture_runs=True)
        if args.save:
            robots._save_listing(
                args.save, "".join(url + "\n" for url in value["urls"])
            )
    except pagefetch.Halt as error:
        raise ValueError("Robots input or fetch was rejected") from error
    warnings = []
    if value["unresolved"]:
        warnings.append("Some relative paths require a base URL")
    return ModuleOutput(
        [Artifact.create("urls", {"urls": value["urls"]})],
        value["run_ids"],
        warnings=warnings,
    )


def _replay(_operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.labs import replay
    from bughunt.modules import replay as command

    plan = command.prepare_args(args)
    output = observations(replay.preview(plan) if dry_run else replay.execute(plan))
    if dry_run:
        output.status = "planned"
    return output


def _lab_result(value: dict, *, dry_run: bool = False) -> ModuleOutput:
    run_ids = [value["run_id"]] if value.get("run_id") else []
    run_ids.extend(
        row["run_id"] for row in value.get("requests", []) if row.get("run_id")
    )
    output = observations(value, run_ids=list(dict.fromkeys(run_ids)))
    if dry_run:
        output.status = "planned"
    return output


def _job_control(
    operation: str, args: Namespace, *, dry_run: bool = False
) -> ModuleOutput:
    from bughunt.core import job

    value = job.status(args.job_id)
    if operation == "cancel" and not dry_run:
        job.cancel(args.job_id)
        output = _effect("job", "cancel-requested", [args.job_id])
        output.warnings.append(
            "Cancellation prevents new work; in-flight I/O may settle"
        )
        return output
    output = inventory("job", value)
    if dry_run:
        output.status = "planned"
    return output


def _race(operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.labs import race

    if operation == "cancel":
        return _job_control(operation, args, dry_run=dry_run)
    plan = race.prepare(
        exchange.read(args.exchange_id),
        mission=args.mission,
        owned_lab=args.owned_lab,
        seconds=args.seconds,
        max_bytes=args.max_bytes,
    )
    return _lab_result(
        race.preview(plan) if dry_run else race.execute(plan), dry_run=dry_run
    )


def _desync(operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.labs import desync

    if operation in {"status", "cancel"}:
        if operation == "cancel":
            return _job_control(operation, args, dry_run=dry_run)
        return _lab_result(desync.status(args.job_id), dry_run=dry_run)
    plan = desync.prepare(
        args.front_url,
        args.backend_url,
        mission=args.mission,
        owned_lab=args.owned_lab,
        seconds=args.seconds,
    )
    return _lab_result(
        desync.preview(plan) if dry_run else desync.execute(plan), dry_run=dry_run
    )


def _ws(operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.labs import websocket

    if operation == "cancel":
        return _job_control(operation, args, dry_run=dry_run)
    if operation == "show":
        output = inventory("websocket-receipt", ledger.export_run(args.run_id))
        output.run_ids.append(args.run_id)
        return output
    options = {
        "mission": args.mission,
        "owned_lab": args.owned_lab,
        "seconds": args.seconds,
    }
    if operation == "capture":
        with Path(args.messages).open("rb") as handle:
            messages = exchange.load_json(handle.read(exchange.INPUT_LIMIT + 1))
        plan = websocket.prepare(args.target, messages, **options)
    else:
        plan = websocket.replay_plan(args.target, **options)
    return _lab_result(
        websocket.preview(plan) if dry_run else websocket.execute(plan), dry_run=dry_run
    )


def _zap(operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.integrations import zap_active, zap_runtime

    if operation == "active":
        plan = zap_active.prepare(
            args.exchange_id,
            mission=args.mission,
            owned_lab=args.owned_lab,
            technology=args.technology,
            requests=args.requests,
            seconds=args.seconds,
            max_bytes=args.body_limit,
        )
        return _lab_result(
            zap_active.preview(plan) if dry_run else zap_runtime.run(plan),
            dry_run=dry_run,
        )
    if operation == "cancel":
        return _job_control(operation, args, dry_run=dry_run)
    if operation == "status":
        return _lab_result(zap_runtime.status(args.job_id), dry_run=dry_run)
    if operation == "show":
        output = inventory("zap-receipt", ledger.export_run(args.run_id))
        output.run_ids.append(args.run_id)
        return output
    return _zap_passive(operation, args, dry_run=dry_run)


def _zap_passive(
    operation: str, args: Namespace, *, dry_run: bool = False
) -> ModuleOutput:
    from bughunt.integrations import zap, zap_import

    if operation == "export":
        if dry_run:
            output = Path(args.output)
            if output.exists():
                raise ValueError("Bundle destination already exists")
            files = zap.build(
                [exchange.read(key) for key in args.exchange_ids],
                args.actor,
                output,
                seconds=args.seconds,
                alerts=args.alerts,
                body_limit=args.body_limit,
            )
            return _planned("zap-bundle", exchange.load_json(files["manifest.json"]))
        return observations(
            zap.export(
                args.exchange_ids,
                args.actor,
                Path(args.output),
                seconds=args.seconds,
                alerts=args.alerts,
                body_limit=args.body_limit,
            )
        )
    with Path(args.report).open("rb") as handle:
        raw = handle.read(exchange.INPUT_LIMIT + 1)
    if dry_run:
        metadata, _normalized = zap_import.prepare_report(
            raw,
            source_id=args.source_id,
            records=[exchange.read(key) for key in args.exchange_id],
        )
        return _planned("zap-report", metadata)
    run_id = zap_import.import_report(
        raw,
        source_id=args.source_id,
        records=[exchange.read(key) for key in args.exchange_id],
    )
    return observations(zap_import.summary(run_id), run_ids=[run_id])


def _planned(resource: str, value: dict) -> ModuleOutput:
    output = inventory(resource, value)
    output.status = "planned"
    return output


def _decode(_operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.modules import decode

    target = args.target.strip()
    if args.timeout <= 0 or args.min < decode._BARE_LENGTH_FLOOR:
        raise ValueError("Invalid decode limits")
    local = Path(target).is_file()
    if not local and decode._remote_refusal(target):
        raise ValueError("Decode target rejected")
    if dry_run:
        return _planned(
            "decode-plan",
            {
                "local": local,
                "minimum": args.min,
                "outbound_actions": 0,
                "will_fetch": not local,
            },
        )
    page = decode._read_local(target) if local else decode._read_remote(args, target)
    if isinstance(page, decode._Stop):
        return ModuleOutput(
            status="blocked" if page.code == 2 else "failed",
            errors=[
                {
                    "code": "decode_source_unavailable",
                    "message": "Page could not be read",
                    "retryable": False,
                }
            ],
        )
    value = decode.unfold(page.text, minimum=args.min, color=False)
    output = inventory(
        "decode-summary", {"decoded": value.decoded, "images": value.images}
    )
    output.artifacts.insert(
        0,
        Artifact.create(
            "document",
            {
                "media_type": "text/plain",
                "text": value.text,
                "truncated": page.truncated,
            },
        ),
    )
    if page.truncated:
        output.status = "partial"
    return output


def _diff(_operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.modules import diff

    urls = diff._vet_fetches(args)
    if dry_run:
        for value in (args.left, args.right):
            if value not in urls:
                diff.load_side(value, None)
        return _planned(
            "diff-plan", {"remote_sources": len(urls), "outbound_actions": 0}
        )
    left, right = diff._load_sides(args, urls)
    output = observations(
        {
            "left": asdict(left),
            "right": asdict(right),
            "body_equal": left.body == right.body,
            "headers_equal": left.headers == right.headers,
            "status_equal": left.status == right.status,
        }
    )
    if left.truncated or right.truncated:
        output.status = "partial"
    return output


def _route_init(args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    import json
    from bughunt.core import route
    from bughunt.modules import route as command

    target = (
        Path(args.path).expanduser()
        if args.path
        else workspace.workspace_dir() / route.CONFIG_FILENAME
    )
    text = (
        json.dumps(
            {"schema_version": route.SCHEMA_VERSION, "interfaces": args.interface},
            indent=2,
        )
        + "\n"
    )
    route.parse_config(text, source=str(target))
    if target.exists() and not args.force:
        raise ValueError("Route configuration exists")
    if dry_run:
        return _planned(
            "route-plan",
            {"interfaces": args.interface, "action": "init", "outbound_actions": 0},
        )
    command._write_atomically(target, text, force=args.force)
    return _effect("route", "init")


def _route(operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.core import route
    from bughunt.modules import route as command

    if operation == "init":
        return _route_init(args, dry_run=dry_run)
    policy, problem = command._load_policy()
    if problem:
        raise ValueError("Invalid route configuration")
    if dry_run:
        return _planned(
            "route-plan",
            {
                "configured": policy is not None,
                "action": operation,
                "outbound_actions": 0,
            },
        )
    if operation == "status":
        return inventory(
            "route",
            command._status_report(policy)
            if policy
            else {"valid": True, "source": None},
        )
    if policy is None:
        output = inventory("route-check", {"ok": False, "reason": "not-configured"})
        output.status = "blocked"
        return output
    host = (workspace.hostname_of(args.host) or args.host.strip()) if args.host else ""
    if host and not workspace.allowed(host):
        raise ValueError("Route target outside scope")
    verdict = route.verify(
        policy, destination=host or None, kind="target", resolver=command._resolver
    )
    output = inventory("route-check", asdict(verdict))
    output.status = "success" if verdict.ok else "blocked"
    return output


def _whois(_operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.modules import whois

    name, server = whois._vet(args)
    if dry_run:
        return _planned(
            "whois-plan",
            {
                "name": name,
                "server": server,
                "queries": 1 if server else 2,
                "outbound_actions": 0,
            },
        )
    text, notes = whois._retrieve(name, server, args)
    record = whois.parse_record(text)
    review = whois.review_notes(record)
    for key in ("created", "expires"):
        if record.get(key) is not None:
            record[key] = record[key].isoformat()
    output = observations({"name": name, "record": record})
    output.warnings.extend([*notes, *review])
    if notes:
        output.status = "partial"
    return output


def _mail(_operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.modules import mail

    request = mail._vet(args)
    if dry_run:
        return _planned(
            "mail-plan",
            {
                "name": request.name,
                "selectors": request.selectors,
                "resolver": request.resolver,
                "outbound_actions": 0,
            },
        )
    found, notes, failed = mail._primary(request)
    spf = mail._published(found["TXT"], "spf")
    dmarc = mail._probe(request, f"_dmarc.{request.name}", "dmarc")
    dkim = [
        (
            selector,
            mail._probe(request, f"{selector}._domainkey.{request.name}", "dkim"),
        )
        for selector in request.selectors
    ]
    summaries = [
        (selector, mail._dkim_summary(probe.record)) for selector, probe in dkim
    ]
    output = observations(
        {
            "name": request.name,
            "mx": found["MX"],
            "spf": spf,
            "dmarc": dmarc._asdict(),
            "dkim": [
                {"selector": selector, **probe._asdict()} for selector, probe in dkim
            ],
        }
    )
    output.warnings.extend(
        [
            *notes,
            *mail._complaints(dmarc, dkim),
            *mail.review_notes(
                found["MX"], spf, dmarc.record, request.selectors, summaries
            ),
        ]
    )
    if failed or dmarc.failed or any(probe.failed for _, probe in dkim):
        output.status = "partial"
    return output


def _redirect(
    _operation: str, args: Namespace, *, dry_run: bool = False
) -> ModuleOutput:
    from itertools import islice
    from bughunt.modules import redirect

    start = args.url.strip()
    if redirect._refusal(args, start):
        raise ValueError("Redirect target or limits rejected")
    if dry_run:
        return _planned(
            "redirect-plan",
            {"target": start, "maximum_hops": args.limit, "outbound_actions": 0},
        )
    hops = []
    try:
        with redirect.client(
            args.timeout,
            insecure=args.insecure,
            cookie=args.cookie,
            authorization=args.authorization,
        ) as client:
            for hop in islice(
                redirect._chain(client, start, redirect._host_key(start)), args.limit
            ):
                hops.append(asdict(hop))
    except redirect._HopFailed:
        output = observations(
            {"target": start, "hops": hops, "classification": "inconclusive"}
        )
        output.errors.append(
            {
                "code": "redirect_fetch_failed",
                "message": "A redirect hop could not be fetched",
                "retryable": False,
            }
        )
        return output
    return observations({"target": start, "hops": hops})


def _forms(_operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.core import pagefetch
    from bughunt.modules import forms

    try:
        if dry_run:
            forms._screen_arguments(args)
            inputs = forms._collect_inputs(args)
            reachable, blocked = forms._split_by_scope(inputs.pages)
            if inputs.pages and not reachable and not inputs.documents:
                raise ValueError("No pages within scope")
            return _planned(
                "forms-plan",
                {
                    "local_documents": len(inputs.documents),
                    "fetches": min(len(reachable), args.limit),
                    "blocked_pages": len(blocked),
                    "save_drafts": args.save_requests,
                    "outbound_actions": 0,
                },
            )
        haul, _inputs, blocked = forms.collect(args, report=False)
        findings = list(forms._distinct(haul.findings, forms._finding_key))
        saved = (
            forms.save_drafts(haul.drafts, report=False) if args.save_requests else []
        )
    except pagefetch.Halt as error:
        raise ValueError("Forms inputs or fetch rejected") from error
    output = observations(
        {
            "findings": [asdict(value) for value in findings[: forms._FINDING_CAP]],
            "unresolved": haul.unresolved,
            "outside_scope": haul.dropped,
            "blocked_pages": len(blocked),
            "drafts_are_captures": False,
        }
    )
    if saved:
        output.artifacts.extend(_effect("request-drafts", "save", saved).artifacts)
    if len(findings) > forms._FINDING_CAP:
        output.status = "partial"
        output.warnings.append("Form findings truncated at the native limit")
    return output


def _silk(_operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.core import pagefetch
    from bughunt.core.results import safe_url
    from bughunt.modules import silk

    try:
        start = silk._starting_point(args)
        if dry_run:
            return _planned(
                "silk-plan",
                {
                    "start": start,
                    "depth": args.depth,
                    "maximum_pages": args.limit,
                    "actor": args.actor,
                    "outbound_actions": 0,
                },
            )
        value = silk._spider_site(args, start, show_banner=False)
        urls = [url for url, _ in value.endpoints]
        if args.save:
            silk._save_list(args.save, urls)
        if workspace.scope_is_active() and not args.no_workspace:
            workspace.remember_urls([url for url in urls if workspace.allowed(url)])
    except pagefetch.Halt as error:
        raise ValueError("Crawl target or fetch rejected") from error
    details = asdict(value)
    details["endpoints"] = [
        {"url": url, "source": source} for url, source in value.endpoints
    ]
    output = observations(details)
    output.artifacts.append(
        Artifact.create("urls", {"urls": [url for url in urls if safe_url(url)]})
    )
    if value.stopped:
        output.warnings.append(value.stopped)
        output.status = "partial"
    return output


def _vhost(_operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from urllib.parse import urlsplit
    from bughunt.modules import vhost

    target, names = vhost._vet(args)
    roster = vhost._admit(
        vhost._unique([urlsplit(target).hostname or "", *names]), args.limit
    )
    if not roster.chosen:
        raise ValueError("No in-scope host candidates")
    if dry_run:
        return _planned(
            "vhost-plan",
            {
                "target": target,
                "names": roster.chosen,
                "outside_scope": roster.skipped,
                "outbound_actions": 0,
            },
        )
    with vhost.client(
        args.timeout,
        insecure=args.insecure,
        cookie=args.cookie,
        authorization=args.authorization,
    ) as client:
        rows = list(vhost._measure(client, target, roster.chosen))
    output = observations(
        {
            "target": target,
            "responses": [
                {
                    "host": row[0],
                    "status": row[1],
                    "bytes": row[2],
                    "title_or_error": row[3],
                    "failed": failed,
                }
                for row, failed in rows
            ],
            "outside_scope": roster.skipped,
            "limit_reached": roster.stopped,
        }
    )
    failures = sum(failed for _, failed in rows)
    if failures:
        output.status = "failed" if failures == len(rows) else "partial"
    return output


def _idor(_operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.modules import idor

    plan = idor.prepare_args(args)
    preview = dry_run or not args.execute
    value = (
        idor.preview(plan)
        if preview
        else idor.execute(plan, allow_write=args.allow_write)
    )
    return _lab_result(value, dry_run=preview)


def _oast(operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.core import oast

    if operation == "show":
        output = inventory("oast-receipt", ledger.export_run(args.run_id))
        output.run_ids.append(args.run_id)
        return output
    if operation == "register":
        function = oast.prepare_registration if dry_run else oast.register
        value = function(args.run_id, provider=args.provider, domain=args.domain)
        output = observations(
            value,
            run_ids=[value["receipt_run_id"]] if value.get("receipt_run_id") else [],
        )
    else:
        with Path(args.file).open("rb") as handle:
            raw = handle.read(exchange.INPUT_LIMIT + 1)
        if dry_run:
            value = oast.prepare_callbacks(raw, source_id=args.source_id)
            output = inventory("oast-import-plan", value)
        else:
            output = observations(oast.import_callbacks(raw, source_id=args.source_id))
    if dry_run:
        output.status = "planned"
    return output


def _repeater(
    _operation: str, args: Namespace, *, dry_run: bool = False
) -> ModuleOutput:
    from bughunt.modules import repeater

    if args.edit:
        return ModuleOutput(
            status="unsupported",
            errors=[
                {
                    "code": "interactive_required",
                    "message": "Use request edits (--method, --path, --header, --body-file) instead of --edit",
                    "retryable": False,
                }
            ],
        )
    try:
        request = repeater._prepare(args)
        if args.timeout <= 0:
            raise ValueError("Timeout must be positive")
        target = repeater._destination(request, args.connect)
        if dry_run:
            return _lab_result(
                {
                    "target": target,
                    "method": request.method,
                    "request_sha256": exchange.digest(repeater.render(request)),
                    "body_bytes": len(request.body),
                    "outbound_actions": 0,
                },
                dry_run=True,
            )
        saved = (
            workspace.save_request(args.save_request, repeater.render(request))
            if args.save_request
            else None
        )
        response, body = repeater.send_request(request, target, args)
        written = repeater._save_output(
            args.output, repeater._raw_reply(response, body)
        )
    except repeater._Stop as error:
        return ModuleOutput(
            status="blocked" if error.status == 2 else "failed",
            errors=[
                {
                    "code": "repeater_stopped",
                    "message": "Request preparation or transmission stopped",
                    "retryable": False,
                }
            ],
        )
    return _repeater_response(args, response, body, saved, written)


def _repeater_response(
    args: Namespace,
    response: "httpx.Response",
    body: bytes,
    saved: Path | None,
    written: int,
) -> ModuleOutput:
    run_id = response.extensions.get("bughunt_run_id")
    output = observations(
        {
            "target": str(response.url),
            "method": response.request.method,
            "status": response.status_code,
            "body_bytes": len(body),
            "body_sha256": exchange.digest(body),
        },
        run_ids=[run_id] if run_id else [],
    )
    if saved:
        output.artifacts.extend(
            _effect("request-drafts", "save", [str(saved)]).artifacts
        )
    if args.output:
        output.artifacts.extend(
            _effect("response-file", "save", [args.output], bool(written)).artifacts
        )
    return output


def _scan_preview(args: Namespace, plan: "ScanPlan", urls: list[str]) -> ModuleOutput:
    from bughunt.core import egress, fastmode
    from bughunt.core.policy import parse_profile

    if args.fast:
        profile = parse_profile(fastmode.build_document(urls, args))
        rows = [
            asdict(profile.decide(url, "active_scan", method=args.method.upper()))
            for url in urls
        ]
        for row, url in zip(rows, urls):
            row["target"] = url
    else:
        rows = [egress.dry_run(url, "active_scan", args.method.upper()) for url in urls]
    output = _lab_result(
        {
            "targets": plan.targets,
            "ports": plan.ports,
            "paths": plan.paths,
            "requests": rows,
            "outbound_actions": 0,
            "will_install_fast_policy": args.fast,
        },
        dry_run=True,
    )
    if not all(row["permitted"] for row in rows):
        output.status = "blocked"
    return output


def _scan_result(
    args: Namespace, reports: list["HostReport"], elapsed: float, code: int
) -> ModuleOutput:
    from bughunt.core import scanner
    from bughunt.core.results import safe_url

    output = observations(scanner.reports_to_json(reports, elapsed))
    urls = sorted(
        {
            hit.final_url
            for report in reports
            for port in report.results
            for hit in port.hits
            if hit.status is not None and safe_url(hit.final_url)
        }
    )
    output.artifacts.append(Artifact.create("urls", {"urls": urls}))
    failures = any(
        not report.resolved
        or any(hit.error for port in report.results for hit in port.hits)
        for report in reports
    )
    if code:
        output.status = "cancelled" if code == 130 else "blocked"
    elif failures:
        output.status = "partial"
    if args.fast:
        output.artifacts.extend(
            _effect("scope-and-policy", "install-fast-policy").artifacts
        )
    return output


def _scan(_operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    import random
    from bughunt.core import egress, execution_receipts, scanner

    with scanner.collect_messages():
        try:
            plan, urls = scanner.prepare_scan(args, dry_run=dry_run)
        except scanner._AbortScan as error:
            raise ValueError("Scan target outside scope") from error
        if dry_run:
            return _scan_preview(args, plan, urls)
        for url in urls:
            egress.authorize(url, "active_scan", args.method.upper())
        if args.proxy and scanner.check_proxy_route(args.proxy) is not None:
            raise egress.PolicyBlocked("proxy-route-blocked")
        if args.random_agent and not args.rotate_agent and plan.agents:
            plan.agents = [random.choice(plan.agents)]
        admissions = execution_receipts.child_admission_observer()
        if admissions is not None:
            admissions(incomplete=True)
        sink = scanner.ArtifactSink(args.save_urls, args.save_source, args.save_headers)
        reports, elapsed, code = scanner.collect_scan(args, plan, sink)
        if code == 0:
            scanner.write_outputs(args, reports, elapsed)
        output = _scan_result(args, reports, elapsed, code)
        output.warnings.append(
            "Raw scanner DNS/TCP/TLS admissions are not fully instrumented; request count is unavailable"
        )
        return output


def _snare_capture(args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.modules import snare

    settings = snare.Settings(
        args.port, args.timeout, args.insecure, args.max_body, args.plain
    )
    limits = {"seconds": args.seconds, "max_exchanges": args.max_exchanges}
    if dry_run:
        return _lab_result(snare.prepare_capture(settings, **limits), dry_run=True)
    value = snare.capture_bounded(settings, **limits)
    output = observations(value, run_ids=value["run_ids"])
    identifiers = []
    for run_id in value["run_ids"]:
        manifest = ledger.manifest_for(run_id)
        if manifest.get("representation") != "raw-http capture":
            continue
        try:
            record = exchange.from_run(run_id)
        except ValueError:
            output.warnings.append(
                "Incomplete capture cannot be handed off as an exchange"
            )
            output.status = "partial"
            continue
        identifiers.extend(
            exchange.save(
                [record],
                source_id=run_id,
                source_bytes=exchange.canonical(manifest),
                kind="ledger",
            )
        )
    output.artifacts.append(Artifact.create("exchanges", {"exchange_ids": identifiers}))
    return output


def _snare(operation: str, args: Namespace, *, dry_run: bool = False) -> ModuleOutput:
    from bughunt.modules import snare

    if operation == "capture":
        return _snare_capture(args, dry_run=dry_run)
    if operation in {"status", "stop"}:
        job = snare._board.live()
        if operation == "stop" and not dry_run and job is not None:
            job.stop.set()
            job.thread.join(snare._JOIN_WAIT)
            output = _effect(
                "snare-listener", "stop", changed=not job.thread.is_alive()
            )
            if job.thread.is_alive():
                output.status = "partial"
            return output
        value = {
            "listening": job is not None,
            "port": job.settings.bound_port if job else None,
        }
        return (
            _planned("snare-listener", value)
            if dry_run
            else inventory("snare-listener", value)
        )
    if operation == "ca":
        if dry_run:
            return _planned(
                "snare-ca", {"certificate_exists": (snare._home() / "ca.crt").exists()}
            )
        existed = all(path.exists() for path in snare._pair_in(snare._home(), "ca"))
        certificate, _key = snare.ensure_ca()
        return _effect("snare-ca", "ensure", [str(certificate)], changed=not existed)
    return ModuleOutput(
        status="unsupported",
        errors=[
            {
                "code": "interactive_required",
                "message": "Use snare capture --seconds 30 --max-exchanges 10 for finite capture",
                "retryable": False,
            }
        ],
    )


_PREPARED_HANDLERS = {
    "robots": _robots,
    "snare": _snare,
    "scan": _scan,
    "repeater": _repeater,
    "oast": _oast,
    "idor": _idor,
    "race": _race,
    "desync": _desync,
    "ws": _ws,
    "zap": _zap,
    "decode": _decode,
    "diff": _diff,
    "route": _route,
    "whois": _whois,
    "mail": _mail,
    "redirect": _redirect,
    "forms": _forms,
    "silk": _silk,
    "vhost": _vhost,
}


def execute(name: str, operation: str, args, context: ExecutionContext) -> ModuleOutput:
    if name in _PREPARED_HANDLERS:
        return _PREPARED_HANDLERS[name](operation, args, dry_run=context.dry_run)
    if context.dry_run:
        if name == "cert":
            return _cert(operation, args, dry_run=True)
        if name == "dns":
            return _dns(operation, args, dry_run=True)
        if name == "discover":
            return _discover(operation, args, dry_run=True)
        if name == "replay":
            return _replay(operation, args, dry_run=True)
        if name == "engine" and operation in {"start", "dry-run"}:
            return _engine(operation, args, dry_run=True)
        output = inventory(
            "module-plan",
            {
                "module_id": name,
                "operation": operation,
                "input_keys": sorted(vars(args)),
                "outbound_actions": 0,
            },
        )
        output.status = "planned"
        return output
    handlers = {
        "scope": _scope,
        "policy": _policy,
        "ledger": _ledger,
        "exchange": _exchange,
        "engine": _engine,
        "discover": _discover,
        "identity": _identity,
        "session": _session,
        "verify": _verify,
        "robots": _robots,
        "clutch": _clutch,
        "blaze": _blaze,
        "quill": _quill,
        "dns": _dns,
        "cert": _cert,
        "replay": _replay,
    }
    if name in handlers:
        return handlers[name](operation, args)
    return _simple_local(name, operation, args)
