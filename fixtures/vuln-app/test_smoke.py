"""Smoke tests for the fixture app (must keep passing after patches)."""
import html


def test_escape_helper():
    assert html.escape("<b>") == "&lt;b&gt;"


def test_param_query_shape():
    query = "SELECT * FROM users WHERE name = ?"
    params = ("alice",)
    assert "?" in query and params == ("alice",)
