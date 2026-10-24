import sys

if __name__ == "__main__":
    if sys.argv[1:2] == ["setup"] and not {"-h", "--help"} & set(sys.argv[2:]):
        from bughunt.console.setup import run

        raise SystemExit(run(sys.argv[2:]))
    from bughunt.console.cli import entry

    entry()
