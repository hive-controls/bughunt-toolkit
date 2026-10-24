# flowcarve

An offline link and endpoint extractor. Point it at a HAR capture, a saved HTTP response, a mitmproxy
flow dump, or any HTML / JavaScript / CSS / JSON text, and it lists every URL and path-like reference
it can find, labeled by kind and by where it was found. You can filter the list, print it, and save it
as txt, json or csv.

flowcarve is a parser, not a proxy. It reads local files (or standard input), never starts mitmproxy,
and never opens a network connection. It only looks at what you give it; it does not request any of the
links it finds.

In the Bughunt console it is the `carve` module (`flowcarve` is an alias), listed under Capture.

## Running it

```
bughunt carve capture.har --unique --sort
bughunt flowcarve app.js page.html --kind absolute-path,js-endpoint --save endpoints.txt
bughunt carve capture.har --include-requests --domain example.com --format csv -o hosts.csv
```

The program is also a plain script, so this works from any directory:

```
python addons/flowcarve/flowcarve.py capture.har --unique --sort
```

It needs only the Python standard library (Python 3.10 or newer).

## Inputs

Give one or more file paths; `-` reads one input from standard input. Inputs are read in order, and a
failure in one does not stop the others.

| Input | How it is recognized | What is extracted |
| --- | --- | --- |
| HAR capture | `.har` / `.zhar` suffix, or a JSON document containing a HAR `log` | Per entry: the request URL, links in the response headers, links in the response body (base64 bodies are decoded) |
| Raw HTTP message | text that starts with an `HTTP/` status line | Links in the headers, then links in the body |
| HTML, JS, CSS, JSON, plain text | everything else that looks like text | Links in the text |
| mitmproxy flow dump | `.mitm`, `.flow`, `.flows`, `.dump` suffix (or a first byte that is not one of `{ [ < # ! H G g h` or whitespace, see Known limits) | Per HTTP flow: request URL, response header links, response body links |
| Images, fonts, audio, video, PDF, archives, wasm | suffix (for example `.png`, `.woff2`, `.mp4`, `.pdf`, `.zip`) | Nothing: the file is not read |

SVG files are scanned like any other text. A response body is only scanned when its content type is
textual; images, fonts, audio, video, PDFs, archives, wasm and protobuf bodies are skipped.

### mitmproxy is optional and not bundled

Everything above except native flow dumps works with the standard library alone. Reading a `.mitm`
dump needs the `mitmproxy` package, which flowcarve imports only at that moment and only as a file
reader:

```
pip install mitmproxy
```

mitmproxy is not vendored, copied or redistributed by Bughunt, and flowcarve never runs it as a proxy.
mitmproxy itself is MIT-licensed, but some packages in its dependency tree carry LGPL terms, so
installing it is your own choice. Without it, a flow dump produces a per-file error that says how to
install it; the other inputs are unaffected. `requirements.txt` lists it as the only optional
dependency. Reading a flow dump from standard input is not supported; pass a file path.

## How links are found

Each input body goes through these passes, in this order. A link found by an earlier pass keeps that
pass's origin if a later pass finds it again.

1. HTML attributes (only when the text contains both `<` and `>`): `href`, `src`, `action`,
   `formaction`, `poster`, `cite`, `icon`, `manifest`, `longdesc`, `data`, every `data-*` attribute,
   `srcset`-style lists, `ping`, and `content` (including `url=` in a meta refresh). Origin `html`.
2. CSS `url(...)` and `@import "..."`. Origin `css`.
3. `sourceMappingURL=` and `sourceURL=` references. Origin `regex`.
4. JSON: when the text is a JSON object or array, every string key and string value. Origin `json`.
5. Absolute `http`, `https`, `ws` and `wss` URLs anywhere in the text, including inside comments.
   Origin `regex`.
6. Protocol-relative `//host/...` URLs. Origin `regex`.
7. Quoted strings (single, double and backtick) that look like links. Origin `regex`.

Unquoted path-looking text is not treated as a link, so `x = /api/unquoted;` and regular-expression
literals are ignored. Schema and namespace URLs (w3.org, json-schema.org and similar), `javascript:`,
`data:`, `blob:`, `file:` and similar schemes, Windows drive paths, MIME types, dates, and system paths
such as `/etc/passwd` are rejected. Percent-encoded links get an extra row for their decoded form,
marked with a `+decoded` suffix on the origin (`html+decoded`, `regex+decoded`). Links from response
headers and request URLs get no decoded twin.

Response headers contribute `Location`, `Content-Location`, `X-Redirect`, the targets of `Link`, and
the URL in `Refresh`, with origin `header`. Request URLs have origin `request` and are hidden unless
you pass `--include-requests`.

### Kinds

| Kind | Meaning |
| --- | --- |
| `https`, `http`, `wss`, `ws` | Absolute URL (a bare `www.host.tld` counts as `https`) |
| `protocol-relative` | Starts with `//` |
| `absolute-path` | Starts with `/` |
| `js-endpoint` | Relative link that contains `api/`, `graphql/`, `ajax/`, `endpoint/` or `v1/`-style segments, or ends in `.js`, `.mjs`, `.cjs`, `.json`, `.php`, `.aspx`, `.jsp`, `.cgi` |
| `relative-path` | Any other relative link |
| `mailto` | `mailto:` address |

### Origins

`request`, `header`, `html`, `css`, `json`, `regex`, each optionally with a `+decoded` suffix.

## Options

| Option | Effect |
| --- | --- |
| `INPUT ...` | Files to read; `-` is standard input |
| `-o`, `--save`, `--output FILE` | Write the resulting rows to FILE (overwrites; the directory must exist) |
| `--format txt\|json\|csv` | Save format; default is chosen from the extension (`.json`, `.csv`, anything else is txt) |
| `--include-requests` | Keep each flow's own request URL as a row |
| `--unique` | Drop repeated rows, keeping the first (keyed on the link, or the resolved URL with `--resolve`) |
| `--sort` | Sort by kind, then by link (case-insensitive) |
| `--group` | Group the on-screen list by kind |
| `--resolve` | Show, save, de-duplicate and sort on the resolved URL instead of the raw link |
| `-v`, `--verbose` | Append the flow URL and status to each row on screen |
| `--kind LIST` | Keep only these kinds (comma-separated) |
| `--origin LIST` | Keep only these origins (comma-separated; compared without `+decoded`) |
| `--contains TEXT` | Keep rows whose link or resolved URL contains TEXT, in any case |
| `--regex PATTERN` | Keep rows whose link or resolved URL matches PATTERN, in any case |
| `--domain LIST` | Keep rows on these domains or their subdomains (comma-separated) |
| `--color auto\|always\|never` | `auto` colors only on a terminal and when `NO_COLOR` is not set |
| `-q`, `--quiet` | Print nothing to standard output (errors still go to standard error) |

Filters are applied in this order: kind, origin, contains, regex, domain, unique, sort. Empty option
values are ignored. `--origin request` only matches when `--include-requests` is also given.

Relative links are resolved against the URL of the flow they came from. This only works for HAR,
mitmproxy and raw-HTTP inputs that carry a URL (an `X-Request-URL` header for raw HTTP); for plain
files the base is the file path, so `--resolve` changes nothing there. Bare `www.` links resolve to
`https://`.

## Output

On screen: a three-line banner with the total and the kinds counted most-first, a blank line, one row
per link (kind, origin, link), a blank line, and `Done. N link(s).`. With no rows it prints only
`No links found.`. Saving prints `Wrote N link(s) to FILE (FORMAT)` unless `--quiet`.

Saved files hold the filtered rows and are written even when there are none:

* `txt`: one link per line (the resolved URL with `--resolve`).
* `json`: an array of objects with the keys `link`, `resolved`, `kind`, `origin`, `flow_url`,
  `status`, `content_type`, `source`, in that order, indented two spaces.
* `csv`: a header line with those same eight columns, then one line per row.

`resolved` is always present in the data, whether or not `--resolve` is set. `flow_url` is the request
URL of the flow (or the input path for plain text), and `source` is the input path or `-`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Normal run. Also: no links found, or some inputs failed but at least one row remained |
| 1 | At least one input could not be read and no rows remained; also an uncaught error (see below) |
| 2 | Command-line error |

A missing file prints `Not found: PATH` and an unreadable one prints `Failed to read PATH: reason`, both
on standard error, and the run continues with the next input.

## Handling captured data

flowcarve prints URLs exactly as they appear in the capture. Query strings can hold session tokens,
API keys and other secrets, and nothing is redacted in the list or in saved files. Treat outputs from
real captures as sensitive. There is no limit on input size or match count; the whole input is read
into memory.

## Known limits

* **Input detection is by name and first bytes.** A file with no `.har` or flow-dump suffix whose first
  byte is not one of `{ [ < # ! H G g h` or a space, tab or newline is taken for a native flow dump.
  That includes a script that starts with `var`, `const`, `function`, `(function`, `//` or `/*`, a
  file that starts with a byte-order mark, and any text beginning with a digit or most lower-case
  letters. Such a file fails with the mitmproxy install hint unless mitmproxy is installed and the
  file really is a dump. Prefixing a newline gets around it, for example
  `(echo; cat app.js) | bughunt carve -`. Standard input is affected the same way, and a flow dump on
  standard input is refused.
* **Raw HTTP status is a string for files.** In a raw-HTTP file the status is the second word of the
  text and is saved as a string (for example `"404"`); in HAR and mitmproxy inputs it is a number.
  Standard input in raw-HTTP form loses the request URL, the status and `X-Request-URL`
  (the flow URL is `-`). A lower-case `http/1.1 200` start is recognized as raw HTTP but gives no status.
* **One malformed token can lose a whole input.** A bracketed host that does not parse (such as
  `https://[bad/x` in an attribute or quoted string) or a one-label host with an out-of-range port
  (`http://intranet:99999`) makes that input fail with `Failed to read ...`. A raw-HTTP file whose whole
  content is the single word `HTTP/1.1` fails with `list index out of range`.
* **Bad `--regex` or `--save`.** An invalid regular expression, or a save path whose directory does
  not exist, ends the run with a Python traceback and exit code 1 (an unwritable save happens after
  the list has been printed).
* **Console encoding.** The banner uses box-drawing characters. On a terminal or pipe whose encoding
  cannot represent them (for example Windows code page 1252 without UTF-8 mode) the listing fails with
  a `UnicodeEncodeError`; `--quiet --save` is unaffected, and `python -X utf8` or `PYTHONUTF8=1` fixes it.
* **Windows line endings.** On Windows the txt and json save files use CRLF line endings (text mode);
  csv files always use CRLF.
* **Repeated header names collapse.** If a response repeats a header name, such as several `Link`
  headers, only the last one is read.
* **Non-ASCII paths.** A path containing non-ASCII characters is not treated as a link; only its
  percent-encoded form is (a full URL with a non-ASCII path is kept).
