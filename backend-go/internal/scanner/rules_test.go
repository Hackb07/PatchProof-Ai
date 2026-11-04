package scanner

import (
	"testing"
)

func ids(source string) map[string]bool {
	out := map[string]bool{}
	for _, f := range ScanSource(source) {
		out[f.RuleID] = true
	}
	return out
}

func TestSQLiPositiveAndNegative(t *testing.T) {
	vuln := "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
	if !ids(vuln)["PY-SQLI-001"] {
		t.Errorf("expected PY-SQLI-001 for %q", vuln)
	}
	safe := "cursor.execute(\"SELECT * FROM users WHERE name = ?\", (name,))\n"
	if ids(safe)["PY-SQLI-001"] {
		t.Errorf("unexpected PY-SQLI-001 for %q", safe)
	}
}

func TestCMDIPositiveAndNegative(t *testing.T) {
	vuln := "import subprocess\nsubprocess.run(f\"ls {d}\", shell=True)\n"
	if !ids(vuln)["PY-CMDI-001"] {
		t.Errorf("expected PY-CMDI-001 for %q", vuln)
	}
	safe := "import subprocess\nsubprocess.run([\"ls\", d], shell=False)\n"
	if ids(safe)["PY-CMDI-001"] {
		t.Errorf("unexpected PY-CMDI-001 for %q", safe)
	}
}

func TestXSSPositiveAndNegative(t *testing.T) {
	vuln := "from flask import render_template_string\nrender_template_string(\"<h1>\" + name + \"</h1>\")\n"
	if !ids(vuln)["PY-XSS-001"] {
		t.Errorf("expected PY-XSS-001 for %q", vuln)
	}
	safe := "import html\nout = \"<h1>\" + html.escape(name) + \"</h1>\"\n"
	if ids(safe)["PY-XSS-001"] {
		t.Errorf("unexpected PY-XSS-001 for %q", safe)
	}
}

func TestPathTraversalPositiveAndNegative(t *testing.T) {
	vuln := "open(f\"/srv/data/{filename}\")\n"
	if !ids(vuln)["PY-PATHTRAV-001"] {
		t.Errorf("expected PY-PATHTRAV-001 for %q", vuln)
	}
	safe := "open(\"/srv/data/static.txt\")\n"
	if ids(safe)["PY-PATHTRAV-001"] {
		t.Errorf("unexpected PY-PATHTRAV-001 for %q", safe)
	}
}

func TestDeserPositiveAndNegative(t *testing.T) {
	vuln := "import pickle\npickle.loads(data)\n"
	if !ids(vuln)["PY-DESER-001"] {
		t.Errorf("expected PY-DESER-001 for %q", vuln)
	}
	safe := "import json\njson.loads(data)\n"
	if ids(safe)["PY-DESER-001"] {
		t.Errorf("unexpected PY-DESER-001 for %q", safe)
	}
}

func TestSecretPositiveAndNegative(t *testing.T) {
	vuln := "API_KEY = \"[REDACTED]\"\n"
	if !ids(vuln)["PY-SECRET-001"] {
		t.Errorf("expected PY-SECRET-001 for %q", vuln)
	}
	safe := "import os\nAPI_KEY = os.environ[\"API_KEY\"]\n"
	if ids(safe)["PY-SECRET-001"] {
		t.Errorf("unexpected PY-SECRET-001 for %q", safe)
	}
}

func TestSSRFPositiveAndNegative(t *testing.T) {
	vuln := "import requests\nrequests.get(f\"https://api.example.com/{path}\")\n"
	if !ids(vuln)["PY-SSRF-001"] {
		t.Errorf("expected PY-SSRF-001 for %q", vuln)
	}
	safe := "ALLOWED = {\"api.example.com\"}\n"
	if ids(safe)["PY-SSRF-001"] {
		t.Errorf("unexpected PY-SSRF-001 for %q", safe)
	}
}

func TestPatchedShapesRescanClean(t *testing.T) {
	// Every shape the deterministic fixer emits must not re-trigger its rule.
	cases := map[string]string{
		"PY-SQLI-001":     "cursor.execute(\"SELECT * FROM users WHERE name = ?\", (name,))\n",
		"PY-CMDI-001":     "import subprocess\nsubprocess.run([\"ls\", d], shell=False)\n",
		"PY-XSS-001":      "import html\nrender_template_string(\"<h1>\" + html.escape(name) + \"</h1>\")\n",
		"PY-PATHTRAV-001": "open(_confined_path(\"/srv/data\", filename))\n",
		"PY-DESER-001":    "import json\njson.loads(data)\n",
		"PY-SECRET-001":   "import os\nAPI_KEY = os.environ[\"API_KEY\"]\n",
		"PY-SSRF-001":     "import requests\nrequests.get(_checked_url(url), timeout=5)\n",
	}
	for ruleID, source := range cases {
		if ids(source)[ruleID] {
			t.Errorf("%s re-triggered by its fixed shape %q", ruleID, source)
		}
	}
}

func TestConstantURLNotFlaggedButVariableIs(t *testing.T) {
	constant := "import requests\nrequests.get(\"https://example.com\")\n"
	if ids(constant)["PY-SSRF-001"] {
		t.Errorf("unexpected PY-SSRF-001 for constant URL")
	}
	variable := "import requests\nrequests.get(url, timeout=5)\n"
	if !ids(variable)["PY-SSRF-001"] {
		t.Errorf("expected PY-SSRF-001 for variable URL")
	}
}

func TestBareShellTrueNotFlagged(t *testing.T) {
	if ids("my_shell=True\n")["PY-CMDI-001"] {
		t.Errorf("unexpected PY-CMDI-001 for my_shell=True")
	}
	if ids("x = 1  # shell=True\n")["PY-CMDI-001"] {
		t.Errorf("unexpected PY-CMDI-001 for comment shell=True")
	}
	// ... but from-imported subprocess calls still are.
	vuln := "from subprocess import run\nrun(cmd, shell=True)\n"
	if !ids(vuln)["PY-CMDI-001"] {
		t.Errorf("expected PY-CMDI-001 for %q", vuln)
	}
}

func TestConstantBinopNotTainted(t *testing.T) {
	if ids("open(\"a\" + \"b\")\n")["PY-PATHTRAV-001"] {
		t.Errorf("unexpected PY-PATHTRAV-001 for constant concat")
	}
	if ids("cursor.execute(\"SELECT \" + \"FROM x\")\n")["PY-SQLI-001"] {
		t.Errorf("unexpected PY-SQLI-001 for constant concat")
	}
	vuln := "open(\"/srv/\" + filename)\n"
	if !ids(vuln)["PY-PATHTRAV-001"] {
		t.Errorf("expected PY-PATHTRAV-001 for %q", vuln)
	}
}

func TestPathJoinShapesFlagged(t *testing.T) {
	if !ids("open(os.path.join(base, name))\n")["PY-PATHTRAV-001"] {
		t.Errorf("expected PY-PATHTRAV-001 for os.path.join")
	}
	if !ids("open(Path(base) / name)\n")["PY-PATHTRAV-001"] {
		t.Errorf("expected PY-PATHTRAV-001 for Path / name")
	}
	if ids("open(\"/srv/data/static.txt\")\n")["PY-PATHTRAV-001"] {
		t.Errorf("unexpected PY-PATHTRAV-001 for constant path")
	}
}

func TestPercentFormatWithoutSpaceFlagged(t *testing.T) {
	vuln := "q = \"SELECT * FROM t WHERE a=%s\" % (v,)\n"
	if !ids(vuln)["PY-SQLI-001"] {
		t.Errorf("expected PY-SQLI-001 for %q", vuln)
	}
}

func TestExecFamilyFlagged(t *testing.T) {
	if !ids("import os\nos.execv(path, args)\n")["PY-CMDI-001"] {
		t.Errorf("expected PY-CMDI-001 for os.execv")
	}
	if !ids("import os\nos.execl(p, a)\n")["PY-CMDI-001"] {
		t.Errorf("expected PY-CMDI-001 for os.execl")
	}
}

func TestTrailingCommentSecretNotFlagged(t *testing.T) {
	code := "x = 1  # password = \"hunter2super\"\n"
	if ids(code)["PY-SECRET-001"] {
		t.Errorf("unexpected PY-SECRET-001 for comment %q", code)
	}
	real := "password = \"hunter2super\"  # rotate me\n"
	if !ids(real)["PY-SECRET-001"] {
		t.Errorf("expected PY-SECRET-001 for %q", real)
	}
}

func TestFullLineCommentsNeverFlagged(t *testing.T) {
	// Advisory comments (e.g. the patcher's own hints) mention sinks by
	// name; like the Python AST walker, the scanner must ignore them.
	comment := "# PatchProof fix (PY-CMDI-001): Use subprocess.run([...], shell=False) with an argv list; never shell=True with input.\n"
	if got := ScanSource(comment); len(got) != 0 {
		t.Errorf("expected no findings for comment, got %v", got)
	}
	xss := "# avoid render_template_string with input\n"
	if got := ScanSource(xss); len(got) != 0 {
		t.Errorf("expected no findings for comment, got %v", got)
	}
}
