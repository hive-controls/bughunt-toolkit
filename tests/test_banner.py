"""Shared banner painter: palette, picture rows, key/value pairs, stderr notes, and the ten module banners."""

import importlib
import io
import re

import pytest

from bughunt.core import banner

CYAN, YELLOW, MAGENTA, WHITE = "\x1b[1;96m", "\x1b[1;93m", "\x1b[1;95m", "\x1b[1;97m"
GREEN, RED, DIM, RESET = "\x1b[1;92m", "\x1b[1;91m", "\x1b[2;96m", "\x1b[0m"

# Each module's coloured banner, recorded before the painter moved to core; escapes are tokens:
# <C> cyan, <Y> yellow, <M> magenta, <D> dim, <0> reset. Decode alone draws its tagline in cyan.
TOKENS = {"<C>": CYAN, "<Y>": YELLOW, "<M>": MAGENTA, "<D>": DIM, "<0>": RESET}
BANNERS = {
    "roost": [
        "<C>            ___<0>",
        "<C>         .-'   `-.<0>",
        "<C>        /   <M>roost<C>  \\<0>",
        "<C>        |  <Y>(<C>o<Y>)<C> <Y>(<C>o<Y>)<C> |<0>",
        "<C>         \\    ^    /<0>",
        "<C>          '-----'<0>",
        "<C>         ===<Y>[<C> <Y>]<C>===<0>",
        "<D>the perch above this engagement<0>",
    ],
    "quill": [
        "<C>               /<0>",
        "<C>              /<0>",
        "<C>             /<0>",
        "<C>            / \\<0>",
        "<C>           | <M>quill<C> |<0>",
        "<C>            \\   /<0>",
        "<C>             <Y>[<C>_<Y>]<C><0>",
        "<D>field notes beside the scope<0>",
    ],
    "blaze": [
        "<C>              <Y>)<C><0>",
        "<C>             <Y>)<C> \\<0>",
        "<C>            <Y>)<C>   <Y>)<C><0>",
        "<C>           ( <M>blaze<C> )<0>",
        "<C>            <Y>)<C>   <Y>)<C><0>",
        "<C>             <Y>)<C> /<0>",
        "<C>             <Y>[<C>_<Y>]<C><0>",
        "<D>trail marks on the url list<0>",
    ],
    "clutch": [
        "<C>            \\\\   //<0>",
        "<C>             \\\\ //<0>",
        "<C>              \\V/<0>",
        "<C>          .--------.<0>",
        "<C>          | <M>clutch<C> |<0>",
        "<C>          '--------'<0>",
        "<C>            <Y>[<C>held<Y>]<C><0>",
        "<D>requests held in the talons<0>",
    ],
    "mail": [
        "<C>    .-----------------.<0>",
        "<C>    |\\               /|<0>",
        "<C>    | \\    <M>mail<C>     / |<0>",
        "<C>    |  \\   <Y>(<C>  <Y>)<C>    /  |<0>",
        "<C>    |   '---------'   |<0>",
        "<C>    '-----------------'<0>",
        "<D>MX, SPF, DKIM, and DMARC for one name<0>",
    ],
    "whois": [
        "<C>     ________________<0>",
        "<C>   .'_<Y>(<C>            <Y>)<C>_'.<0>",
        "<C>   |    registrar    |<0>",
        "<C>   |     (<M>whois<C>)     |<0>",
        "<C>   '-----------------'<0>",
        "<D>registrar, dates, and nameservers for one domain<0>",
    ],
    "jwt": [
        "<C>          .----.<0>",
        "<C>         /  <Y>(<C><Y>)<C>  \\<0>",
        "<C>        |  <M>jwt<C>  |<0>",
        "<C>         \\  ||  /<0>",
        "<C>          '----'<0>",
        "<C>            ||<0>",
        "<C>          <Y>[<C>key<Y>]<C><0>",
        "<D>header and claims, with the signature left unchecked<0>",
    ],
    "silk": [
        "<C>         \\    ^    /<0>",
        "<C>       .  \\   |   /  .<0>",
        "<C>     <Y>(<C>     \\  |  /     <Y>)<C><0>",
        "<C>      ' .   --+--   . '<0>",
        "<C>         /    |    \\<0>",
        "<C>        /     |     \\<0>",
        "<C>           <M>silk<C><0>",
        "<D>spins pages, robots.txt, and sitemaps into endpoints<0>",
    ],
    "decode": [
        "<C>        .------.<0>",
        "<C>      .'        '.<0>",
        "<C>     /   <M>decode<C>   \\<0>",
        "<C>    |    <Y>(<C>    <Y>)<C>    |<0>",
        "<C>     \\   '----'   /<0>",
        "<C>      '.        .'<0>",
        "<C>        '------'<0>",
        "<C>page source, with non-image base64 written out as text<0>",
    ],
    "snare": [
        "<C>              \\   |   /<0>",
        "<C>               \\  |  /<0>",
        "<C>            .---\\ | /---.<0>",
        "<C>           /     \\|/     \\<0>",
        "<C>          |     <M>snare<C>     |<0>",
        "<C>           \\     /|\\     /<0>",
        "<C>            '---/ | \\---'<0>",
        "<C>               /  |  \\<0>",
        "<C>              /   |   \\<0>",
        "<C>                <Y>[<C>web<Y>]<C><0>",
        "<D>the web the browser flies into<0>",
    ],
}


def expand(marked_rows):
    text = "\n".join(marked_rows)
    for token, escape in TOKENS.items():
        text = text.replace(token, escape)
    return text


def strip_tokens(marked_rows):
    return re.sub(r"<[CYMD0]>", "", "\n".join(marked_rows))


@pytest.mark.parametrize("name", sorted(BANNERS))
def test_each_module_banner_keeps_its_coloured_bytes(name):
    module = importlib.import_module(f"bughunt.modules.{name}")
    assert module.format_banner(True) == expand(BANNERS[name])


@pytest.mark.parametrize("name", sorted(BANNERS))
def test_each_module_banner_keeps_its_plain_bytes(name):
    module = importlib.import_module(f"bughunt.modules.{name}")
    assert module.format_banner(False) == strip_tokens(BANNERS[name])


def test_only_decode_draws_its_tagline_in_cyan():
    cyan_tagline = [name for name, rows in BANNERS.items() if rows[-1].startswith("<C>")]
    assert cyan_tagline == ["decode"]


def test_the_palette_is_the_eight_sequences_every_banner_is_drawn_with():
    assert tuple(banner.ANSI) == (CYAN, YELLOW, MAGENTA, WHITE, GREEN, RED, DIM, RESET)
    assert banner.Ink._fields == ("cyan", "yellow", "magenta", "white", "green", "red", "dim", "reset")


def test_the_bare_palette_has_every_sequence_empty():
    assert set(banner.BARE) == {""}
    assert len(banner.BARE) == len(banner.ANSI)


def test_ink_picks_real_sequences_only_with_colour():
    assert banner.ink(True) is banner.ANSI
    assert banner.ink(False) is banner.BARE


def test_sgr_builds_one_escape_sequence():
    assert banner.sgr("1;96") == CYAN
    assert banner.sgr("0") == RESET


def test_wrap_closes_the_text_with_a_reset():
    assert banner.ANSI.wrap("green", "ok") == f"{GREEN}ok{RESET}"
    assert banner.ANSI.wrap("red", "") == f"{RED}{RESET}"


def test_wrap_with_the_bare_palette_is_the_text_itself():
    assert banner.BARE.wrap("magenta", "text") == "text"


def test_wrap_rejects_a_hue_the_palette_does_not_have():
    with pytest.raises(AttributeError):
        banner.ANSI.wrap("purple", "text")


def test_art_rows_pads_each_row_on_the_left():
    assert banner.art_rows([(0, "a"), (3, "bc"), (1, "")]) == ["a", "   bc", " "]


def test_art_rows_of_nothing_is_empty():
    assert banner.art_rows([]) == []


def test_paint_row_colours_the_nameplate_and_leaves_the_rest_cyan():
    painted = banner.paint_row("| mark |", "mark", banner.ANSI)
    assert painted == f"{CYAN}| {MAGENTA}mark{CYAN} |{RESET}"


def test_paint_row_accents_each_bracket_when_the_row_has_no_nameplate():
    painted = banner.paint_row("(a)[b]", "mark", banner.ANSI)
    accent = {glyph: f"{YELLOW}{glyph}{CYAN}" for glyph in "()[]"}
    assert painted == f"{CYAN}{accent['(']}a{accent[')']}{accent['[']}b{accent[']']}{RESET}"


def test_paint_row_keeps_brackets_cyan_in_the_row_holding_the_nameplate():
    painted = banner.paint_row("( mark )", "mark", banner.ANSI)
    assert painted == f"{CYAN}( {MAGENTA}mark{CYAN} ){RESET}"


def test_paint_row_colours_only_the_first_nameplate():
    painted = banner.paint_row("mark mark", "mark", banner.ANSI)
    assert painted == f"{CYAN}{MAGENTA}mark{CYAN} mark{RESET}"


def test_paint_row_with_the_bare_palette_returns_the_row_unchanged():
    for row in ("| mark |", "(a)[b]", "", "    "):
        assert banner.paint_row(row, "mark", banner.BARE) == row


def test_render_banner_draws_rows_then_a_dim_tagline_by_default():
    drawn = banner.render_banner(["| mark |", "[_]"], "mark", "the tagline", True)
    expected = [
        f"{CYAN}| {MAGENTA}mark{CYAN} |{RESET}",
        f"{CYAN}{YELLOW}[{CYAN}_{YELLOW}]{CYAN}{RESET}",
        f"{DIM}the tagline{RESET}",
    ]
    assert drawn == "\n".join(expected)


def test_render_banner_takes_the_tagline_hue_by_name():
    drawn = banner.render_banner(["row"], "mark", "tag", True, tagline_hue="cyan")
    assert drawn.split("\n")[-1] == f"{CYAN}tag{RESET}"


def test_render_banner_without_colour_is_the_rows_and_tagline_as_written():
    assert banner.render_banner(["| mark |", "[_]"], "mark", "the tagline", False) == "| mark |\n[_]\nthe tagline"


def test_render_banner_accepts_any_iterable_of_rows():
    rows = (row for row in ("a", "b"))
    assert banner.render_banner(rows, "mark", "tag", False) == "a\nb\ntag"


def test_the_plain_banner_is_the_coloured_one_without_escapes():
    rows = banner.art_rows([(2, "(x) mark"), (4, "[y]")])
    coloured = banner.render_banner(rows, "mark", "tag", True)
    assert re.sub(r"\x1b\[[0-9;]*m", "", coloured) == banner.render_banner(rows, "mark", "tag", False)


def test_format_pair_plain_is_key_tab_value():
    assert banner.format_pair("host", "example.com", False) == "host\texample.com"


def test_format_pair_colour_pads_the_key_to_twelve_columns():
    assert banner.format_pair("host", "example.com", True) == (
        f"  {CYAN}host        {RESET} {WHITE}example.com{RESET}"
    )


def test_format_pair_does_not_cut_a_long_key():
    assert banner.format_pair("a-very-long-key", "v", True) == f"  {CYAN}a-very-long-key{RESET} {WHITE}v{RESET}"


def test_format_pair_dim_changes_only_the_value_hue():
    assert banner.format_pair("signature", "absent", True, dim=True) == (
        f"  {CYAN}signature   {RESET} {DIM}absent{RESET}"
    )
    assert banner.format_pair("signature", "absent", False, dim=True) == "signature\tabsent"


def test_format_pair_dim_is_keyword_only():
    with pytest.raises(TypeError):
        banner.format_pair("k", "v", True, True)


class Stderr(io.StringIO):
    def __init__(self, tty):
        super().__init__()
        self.tty = tty

    def isatty(self):
        return self.tty


def test_note_on_a_colour_terminal_is_yellow(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    stderr = Stderr(True)
    monkeypatch.setattr("sys.stderr", stderr)
    banner.note("review: no exp")
    assert stderr.getvalue() == f"{YELLOW}review: no exp{RESET}\n"


@pytest.mark.parametrize("tty", [True, False])
def test_note_is_plain_without_colour(monkeypatch, tty):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("TERM", "xterm")
    stderr = Stderr(tty)
    monkeypatch.setattr("sys.stderr", stderr)
    banner.note("review: no exp")
    assert stderr.getvalue() == "review: no exp\n"


def test_note_is_plain_when_stderr_is_piped(monkeypatch, capsys):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    banner.note("careful")
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", "careful\n")
