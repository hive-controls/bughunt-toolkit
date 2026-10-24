"""Authorized HTTP testing tools and supporting integrations."""

VERSION = "2.15.0"

__all__ = [
    "VERSION",
    "Artifact",
    "Result",
    "run_module",
    "catalog",
    "load_pipeline",
    "run_pipeline",
    "resume_pipeline",
]


def __getattr__(name):
    if name in {"Artifact", "Result"}:
        from bughunt.core import results

        return getattr(results, name)
    if name in {"run_module", "catalog"}:
        from bughunt.core import api

        return getattr(api, name)
    if name in {"load_pipeline", "run_pipeline", "resume_pipeline"}:
        from bughunt.core import pipeline

        return getattr(pipeline, name)
    raise AttributeError(name)
