"""Digest-keyed parse reuse in policy.read_document: the file is re-read every call, parsed once per content.

Mutation proofs (each verified RED by hand-editing policy.read_document):
- cache disabled (always parse)                -> test_parse_count_is_per_unique_content fails
- key by mtime instead of sha256(bytes)        -> test_same_mtime_rewrite_is_reparsed_and_redecided fails
- cache failures as success                    -> test_malformed_policy_is_never_cached fails
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading

import pytest

from bughunt.core import egress, policy
from bughunt.modules import policy as command

TARGET = "https://lab.example/api/objects"


@pytest.fixture
def policy_file(tmp_path, monkeypatch):
    document = command.example_document()
    document["state"] = "verified"
    document["verified_at"] = datetime.now(timezone.utc).isoformat()
    document["assets"][0]["origin"] = "https://lab.example"
    document["exclusions"][0]["origin"] = "https://lab.example"
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    monkeypatch.setattr(policy, "_parsed_entry", None)
    return path, document


@pytest.fixture
def parse_calls(monkeypatch):
    calls = []
    original = policy.parse_profile

    def counting(value):
        calls.append(1)
        return original(value)

    monkeypatch.setattr(policy, "parse_profile", counting)
    return calls


def test_parse_count_is_per_unique_content(policy_file, parse_calls, monkeypatch):
    path, document = policy_file
    reads = []
    original_read = Path.read_bytes

    def counting_read(self):
        reads.append(1)
        return original_read(self)

    monkeypatch.setattr(Path, "read_bytes", counting_read)
    for _ in range(50):
        egress.authorize(TARGET, "manual")
    assert len(reads) == 50, "every authorize must still re-read the file"
    assert len(parse_calls) == 1
    document["policy_version"] = "2"
    path.write_text(json.dumps(document), encoding="utf-8")
    for _ in range(20):
        egress.authorize(TARGET, "manual")
    assert len(parse_calls) == 2


def test_same_mtime_rewrite_is_reparsed_and_redecided(policy_file, parse_calls):
    path, document = policy_file
    before = egress.authorize(TARGET, "manual")
    stamp = path.stat()
    original_text = path.read_text(encoding="utf-8")
    revoked = json.loads(original_text)
    revoked["permissions"]["manual"] = False
    new_text = json.dumps(revoked)
    path.write_text(new_text, encoding="utf-8")
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    assert path.stat().st_mtime_ns == stamp.st_mtime_ns
    with pytest.raises(egress.PolicyBlocked):
        egress.authorize(TARGET, "manual")
    assert len(parse_calls) == 2
    assert egress.current_profile() != before


def test_malformed_policy_is_never_cached(policy_file, parse_calls):
    path, document = policy_file
    egress.authorize(TARGET, "manual")
    path.write_text(json.dumps(dict(document, schema_version=2)), encoding="utf-8")
    for _ in range(3):
        with pytest.raises(egress.PolicyBlocked):
            egress.current_profile()
    assert len(parse_calls) == 4
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(egress.PolicyBlocked):
        egress.current_profile()


def test_cache_is_bounded_and_thread_safe(policy_file):
    path, document = policy_file
    variants = [json.dumps(dict(document, policy_version=str(n + 1))) for n in range(4)]
    contents = {}
    errors = []
    for text in variants:
        contents[text] = json.loads(text)["policy_version"]
    barrier = threading.Barrier(8)

    def hammer(index):
        try:
            barrier.wait()
            for round_number in range(40):
                text = variants[(index + round_number) % 4]
                path.write_text(text, encoding="utf-8")
                try:
                    _, profile = policy.read_document(path)
                except policy.PolicyError:
                    continue  # torn write by the test's own concurrent writers
                assert profile.policy_version in {"1", "2", "3", "4"}
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=hammer, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert isinstance(policy._parsed_entry, tuple) and len(policy._parsed_entry) == 2
