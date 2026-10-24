"""Reading robots.txt rules and sitemap entries."""

import pytest

from bughunt.core import crawlhints


@pytest.mark.parametrize(("text", "expected"), [
    ("", []),
    ("<urlset><url><loc>https://a.test/1</loc></url><url><loc>https://a.test/2</loc></url></urlset>",
     ["https://a.test/1", "https://a.test/2"]),
    ("<LOC>\n   https://a.test/x?a=1&amp;b=2  \n</LOC>", ["https://a.test/x?a=1&b=2"]),
    ("<loc>   </loc><loc>https://a.test/kept</loc>", ["https://a.test/kept"]),
    ("no sitemap markup at all", []),
])
def test_sitemap_locs(text, expected):
    assert crawlhints.sitemap_locs(text) == expected


@pytest.mark.parametrize(("text", "expected"), [
    ("<sitemapindex><sitemap><loc>https://a.test/s.xml</loc></sitemap></sitemapindex>", True),
    ("<SitemapIndex>", True),
    ("<urlset></urlset>", False),
    (" " * crawlhints.INDEX_SNIFF + "<sitemapindex>", False),
    (" " * (crawlhints.INDEX_SNIFF - 20) + "<sitemapindex>", True),
])
def test_is_sitemap_index_only_looks_at_the_start(text, expected):
    assert crawlhints.is_sitemap_index(text) is expected


@pytest.mark.parametrize(("value", "expected"), [
    ("/private/", "/private/"),
    ("  /private/  ", "/private/"),
    ("/exact$", "/exact"),
    ("/prefix/*", "/prefix/"),
    ("/both/*$", "/both/"),
    ("/*.js", "/*.js"),
    ("*", ""),
    ("", ""),
    ("   ", ""),
    ("$", ""),
])
def test_rule_path(value, expected):
    assert crawlhints.rule_path(value) == expected


def test_directives_lower_the_key_strip_the_value_and_drop_comments():
    text = "\n".join([
        "# a comment line",
        "User-Agent: *",
        "Disallow: /admin/   # keep out",
        "ALLOW:/public",
        "no colon on this line",
        "Sitemap: https://a.test/sitemap.xml",
        "",
    ])
    assert list(crawlhints.directives(text)) == [
        ("user-agent", "*"),
        ("disallow", "/admin/"),
        ("allow", "/public"),
        ("sitemap", "https://a.test/sitemap.xml"),
    ]


def test_directives_keep_every_colon_after_the_first_in_the_value():
    assert list(crawlhints.directives("Host: example.com:8080")) == [("host", "example.com:8080")]
