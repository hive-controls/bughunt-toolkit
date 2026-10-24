import bughunt
from bughunt.core import ledger
from bughunt.core.pipeline_budget import Governor, bind
from test_oracle_mod_g1_recon import (
    NAME,
    Reply,
    a_data,
    dns_lab,
    lab,
    resolver,
    tls_edge,
)


def test_dns_api_returns_real_udp_records_and_action_receipt(dns_lab, capsys):
    dns_lab.resolver.on(NAME, 1, Reply(answers=[(1, a_data("192.0.2.7"))]))
    result = bughunt.run_module(
        "dns",
        options={"name": NAME, "resolver": "127.0.0.1", "port": dns_lab.resolver.port},
    )
    assert result.status == "success", result.to_dict()
    assert result.artifacts[0].payload["records"] == [
        {"name": NAME, "type": "A", "ttl": 30, "value": "192.0.2.7"},
    ]
    assert len(dns_lab.resolver.seen) == 6
    assert len(result.evidence) == 1
    assert (
        ledger.export_run(result.evidence[0]["run_id"])["manifest"]["representation"]
        == "action-only; no raw exchange captured"
    )
    assert capsys.readouterr() == ("", "")


def test_dns_api_preview_validates_without_datagrams(dns_lab):
    options = {"name": NAME, "resolver": "127.0.0.1", "port": dns_lab.resolver.port}
    result = bughunt.run_module("dns", options=options, dry_run=True)
    assert result.status == "planned"
    assert result.artifacts[0].payload["items"][0]["planned_queries"] == 6
    assert dns_lab.resolver.seen == []
    assert not ledger.runs_dir().exists()


def test_dns_api_obeys_shared_cap_at_actual_datagram_send(dns_lab):
    governor = Governor(
        {
            "requests": 2,
            "seconds": 30,
            "concurrency": 1,
            "requests_per_second": 100,
            "bytes": 100000,
        }
    )
    with bind(governor):
        result = bughunt.run_module(
            "dns",
            options={
                "name": NAME,
                "resolver": "127.0.0.1",
                "port": dns_lab.resolver.port,
            },
        )
    assert result.status == "blocked", result.to_dict()
    assert len(dns_lab.resolver.seen) == governor.requests_admitted == 2
    assert len(result.evidence) == 1


def test_certificate_boundary_consumes_shared_admission(lab, tls_edge):
    import pytest
    from bughunt.core import egress
    from bughunt.modules import cert

    governor = Governor(
        {
            "requests": 1,
            "seconds": 30,
            "concurrency": 1,
            "requests_per_second": 100,
            "bytes": 100000,
        }
    )
    with bind(governor):
        assert cert.fetch_certificate(NAME, 443, 2)
        with pytest.raises(egress.PolicyBlocked, match="pipeline-request-cap"):
            cert.fetch_certificate(NAME, 443, 2)
    assert governor.requests_admitted == len(tls_edge.dialled) == 1


def test_certificate_api_reads_actual_owned_tls_server(lab, tmp_path, capsys):
    from scanner_oracle_support import LabServer, make_self_signed_certificate

    material = make_self_signed_certificate(tmp_path)
    assert material is not None, "OpenSSL is required for owned TLS acceptance"
    server = LabServer(tls=material)
    try:
        lab.set_scope(NAME, "127.0.0.1")
        lab.grant(f"https://127.0.0.1:{server.port}")
        result = bughunt.run_module(
            "cert", options={"host": "127.0.0.1", "port": server.port}
        )
        assert result.status == "success", result.to_dict()
        payload = result.artifacts[0].payload
        assert payload["port"] == server.port
        assert payload["subject"]["text"] and payload["issuer"]["text"]
        assert (
            result.evidence[0]["representation"]
            == "action-only; no raw exchange captured"
        )
        assert capsys.readouterr() == ("", "")
    finally:
        server.close()
