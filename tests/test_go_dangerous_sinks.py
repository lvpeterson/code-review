from languages.go.dangerous_sinks import detect_dangerous_sinks


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_exec_command_with_non_literal_arg_is_flagged(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        "import \"os/exec\"\n\n"
        "func run(userInput string) {\n"
        "\texec.Command(\"sh\", \"-c\", userInput)\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "CMD-001" for f in findings)


def test_exec_command_with_all_literal_args_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        "import \"os/exec\"\n\n"
        "func run() {\n"
        "\texec.Command(\"ls\", \"-la\")\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert not any(f.check_id == "CMD-001" for f in findings)


def test_os_read_file_with_non_literal_path_is_flagged(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        "import \"os\"\n\n"
        "func read(userPath string) {\n"
        "\tos.ReadFile(userPath)\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "PATH-001" for f in findings)


def test_os_read_file_with_literal_path_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        "import \"os\"\n\n"
        "func read() {\n"
        "\tos.ReadFile(\"config.json\")\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert not any(f.check_id == "PATH-001" for f in findings)


def test_http_get_with_non_literal_url_is_flagged(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        "import \"net/http\"\n\n"
        "func proxy(targetUrl string) {\n"
        "\thttp.Get(targetUrl)\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "SSRF-001" for f in findings)


def test_http_get_with_literal_url_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        "import \"net/http\"\n\n"
        "func get() {\n"
        "\thttp.Get(\"https://api.example.com/data\")\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert not any(f.check_id == "SSRF-001" for f in findings)


def test_http_new_request_with_non_literal_url_is_flagged(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        "import \"net/http\"\n\n"
        "func proxy(targetUrl string) {\n"
        "\thttp.NewRequest(\"GET\", targetUrl, nil)\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "SSRF-001" for f in findings)


def test_net_http_redirect_with_non_literal_url_is_flagged(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        "import \"net/http\"\n\n"
        "func handler(w http.ResponseWriter, r *http.Request, next string) {\n"
        "\thttp.Redirect(w, r, next, http.StatusFound)\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "REDIRECT-001" for f in findings)


def test_gin_context_redirect_with_non_literal_url_is_flagged(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        "import \"net/http\"\n\n"
        "func handler(c *gin.Context, next string) {\n"
        "\tc.Redirect(http.StatusFound, next)\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "REDIRECT-001" for f in findings)


def test_redirect_with_literal_url_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        "import \"net/http\"\n\n"
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        "\thttp.Redirect(w, r, \"/login\", http.StatusFound)\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert not any(f.check_id == "REDIRECT-001" for f in findings)
