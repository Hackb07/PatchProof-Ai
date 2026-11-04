//! Positive + negative cases for every MVP rule (ports
//! `backend/tests/test_rules.py`).

use std::collections::{HashMap, HashSet};

use patchproof_core::scanner::rules::scan_source;

fn ids(source: &str) -> HashSet<String> {
    scan_source(source).into_iter().map(|f| f.rule_id).collect()
}

#[test]
fn test_sqli_positive_and_negative() {
    let vuln = "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n";
    assert!(ids(vuln).contains("PY-SQLI-001"));
    let safe = "cursor.execute(\"SELECT * FROM users WHERE name = ?\", (name,))\n";
    assert!(!ids(safe).contains("PY-SQLI-001"));
}

#[test]
fn test_cmdi_positive_and_negative() {
    let vuln = "import subprocess\nsubprocess.run(f\"ls {d}\", shell=True)\n";
    assert!(ids(vuln).contains("PY-CMDI-001"));
    let safe = "import subprocess\nsubprocess.run([\"ls\", d], shell=False)\n";
    assert!(!ids(safe).contains("PY-CMDI-001"));
}

#[test]
fn test_xss_positive_and_negative() {
    let vuln = "from flask import render_template_string\nrender_template_string(\"<h1>\" + name + \"</h1>\")\n";
    assert!(ids(vuln).contains("PY-XSS-001"));
    let safe = "import html\nout = \"<h1>\" + html.escape(name) + \"</h1>\"\n";
    assert!(!ids(safe).contains("PY-XSS-001"));
}

#[test]
fn test_pathtraversal_positive_and_negative() {
    let vuln = "open(f\"/srv/data/{filename}\")\n";
    assert!(ids(vuln).contains("PY-PATHTRAV-001"));
    let safe = "open(\"/srv/data/static.txt\")\n";
    assert!(!ids(safe).contains("PY-PATHTRAV-001"));
}

#[test]
fn test_deser_positive_and_negative() {
    let vuln = "import pickle\npickle.loads(data)\n";
    assert!(ids(vuln).contains("PY-DESER-001"));
    let safe = "import json\njson.loads(data)\n";
    assert!(!ids(safe).contains("PY-DESER-001"));
}

#[test]
fn test_secret_positive_and_negative() {
    let vuln = "API_KEY = \"sk-live-abc123\"\n";
    assert!(ids(vuln).contains("PY-SECRET-001"));
    let safe = "import os\nAPI_KEY = os.environ[\"API_KEY\"]\n";
    assert!(!ids(safe).contains("PY-SECRET-001"));
}

#[test]
fn test_ssrf_positive_and_negative() {
    let vuln = "import requests\nrequests.get(f\"https://api.example.com/{path}\")\n";
    assert!(ids(vuln).contains("PY-SSRF-001"));
    let safe = "ALLOWED = {\"api.example.com\"}\n";
    assert!(!ids(safe).contains("PY-SSRF-001"));
}

#[test]
fn test_patched_shapes_rescan_clean() {
    // Every shape the deterministic fixer emits must not re-trigger its rule.
    let cases = HashMap::from([
        (
            "PY-SQLI-001",
            "cursor.execute(\"SELECT * FROM users WHERE name = ?\", (name,))\n",
        ),
        (
            "PY-CMDI-001",
            "import subprocess\nsubprocess.run([\"ls\", d], shell=False)\n",
        ),
        (
            "PY-XSS-001",
            "import html\nrender_template_string(\"<h1>\" + html.escape(name) + \"</h1>\")\n",
        ),
        (
            "PY-PATHTRAV-001",
            "open(_confined_path(\"/srv/data\", filename))\n",
        ),
        ("PY-DESER-001", "import json\njson.loads(data)\n"),
        (
            "PY-SECRET-001",
            "import os\nAPI_KEY = os.environ[\"API_KEY\"]\n",
        ),
        (
            "PY-SSRF-001",
            "import requests\nrequests.get(_checked_url(url), timeout=5)\n",
        ),
    ]);
    for (rule_id, source) in cases {
        assert!(!ids(source).contains(rule_id), "{rule_id}");
    }
}

#[test]
fn test_constant_url_not_flagged_but_variable_is() {
    let constant = "import requests\nrequests.get(\"https://example.com\")\n";
    assert!(!ids(constant).contains("PY-SSRF-001"));
    let variable = "import requests\nrequests.get(url, timeout=5)\n";
    assert!(ids(variable).contains("PY-SSRF-001"));
}

#[test]
fn test_bare_shell_true_not_flagged() {
    assert!(!ids("my_shell=True\n").contains("PY-CMDI-001"));
    assert!(!ids("x = 1  # shell=True\n").contains("PY-CMDI-001"));
    // ... but from-imported subprocess calls still are.
    let vuln = "from subprocess import run\nrun(cmd, shell=True)\n";
    assert!(ids(vuln).contains("PY-CMDI-001"));
}

#[test]
fn test_constant_binop_not_tainted() {
    assert!(!ids("open(\"a\" + \"b\")\n").contains("PY-PATHTRAV-001"));
    assert!(!ids("cursor.execute(\"SELECT \" + \"FROM x\")\n").contains("PY-SQLI-001"));
    let vuln = "open(\"/srv/\" + filename)\n";
    assert!(ids(vuln).contains("PY-PATHTRAV-001"));
}

#[test]
fn test_path_join_shapes_flagged() {
    assert!(ids("open(os.path.join(base, name))\n").contains("PY-PATHTRAV-001"));
    assert!(ids("open(Path(base) / name)\n").contains("PY-PATHTRAV-001"));
    assert!(!ids("open(\"/srv/data/static.txt\")\n").contains("PY-PATHTRAV-001"));
}

#[test]
fn test_percent_format_without_space_flagged() {
    let vuln = "q = \"SELECT * FROM t WHERE a=%s\" % (v,)\n";
    assert!(ids(vuln).contains("PY-SQLI-001"));
}

#[test]
fn test_exec_family_flagged() {
    assert!(ids("import os\nos.execv(path, args)\n").contains("PY-CMDI-001"));
    assert!(ids("import os\nos.execl(p, a)\n").contains("PY-CMDI-001"));
}

#[test]
fn test_trailing_comment_secret_not_flagged() {
    let code = "x = 1  # password = \"hunter2super\"\n";
    assert!(!ids(code).contains("PY-SECRET-001"));
    let real = "password = \"hunter2super\"  # rotate me\n";
    assert!(ids(real).contains("PY-SECRET-001"));
}

#[test]
fn test_full_line_comments_never_flagged() {
    // Advisory comments (e.g. the patcher's own hints) mention sinks by
    // name; like the Python AST walker, the scanner must ignore them.
    let comment = "# PatchProof fix (PY-CMDI-001): Use subprocess.run([...], shell=False) with an argv list; never shell=True with input.\n";
    assert!(scan_source(comment).is_empty());
    let xss = "# avoid render_template_string with input\n";
    assert!(scan_source(xss).is_empty());
}
