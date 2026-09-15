from languages.javascript.dangerous_sinks import detect_dangerous_sinks


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_exec_with_non_literal_command_is_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "const { exec } = require('child_process')\n\n"
        "function run(userInput) {\n"
        "  exec(userInput)\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "CMD-001" for f in findings)


def test_exec_with_literal_command_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "const { exec } = require('child_process')\n\n"
        "exec('ls -la')\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert not any(f.check_id == "CMD-001" for f in findings)


def test_spawn_without_shell_option_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "const { spawn } = require('child_process')\n\n"
        "function run(userInput) {\n"
        "  spawn('ls', [userInput])\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert not any(f.check_id == "CMD-001" for f in findings)


def test_spawn_with_shell_true_is_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "const { spawn } = require('child_process')\n\n"
        "function run(userInput) {\n"
        "  spawn(userInput, [], { shell: true })\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "CMD-001" for f in findings)


def test_read_file_with_non_literal_path_is_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "const fs = require('fs')\n\n"
        "function read(userPath) {\n"
        "  fs.readFile(userPath, 'utf8', () => {})\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "PATH-001" for f in findings)


def test_read_file_with_literal_path_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "const fs = require('fs')\n\n"
        "fs.readFile('config.json', 'utf8', () => {})\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert not any(f.check_id == "PATH-001" for f in findings)


def test_path_join_argument_passed_to_read_file_is_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "const fs = require('fs')\n"
        "const path = require('path')\n\n"
        "function read(userFile) {\n"
        "  fs.readFileSync(path.join(__dirname, userFile))\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "PATH-001" for f in findings)


def test_fetch_with_non_literal_url_is_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "async function proxy(targetUrl) {\n"
        "  return fetch(targetUrl)\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "SSRF-001" for f in findings)


def test_express_res_redirect_with_non_literal_target_is_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "function handler(req, res) {\n"
        "  res.redirect(req.query.next)\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "REDIRECT-001" for f in findings)


def test_hono_c_redirect_with_non_literal_target_is_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "function handler(c) {\n"
        "  return c.redirect(c.req.query('next'))\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "REDIRECT-001" for f in findings)


def test_redirect_with_literal_target_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "function handler(req, res) {\n"
        "  res.redirect('/login')\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert not any(f.check_id == "REDIRECT-001" for f in findings)


def test_route_registration_get_call_is_not_flagged_as_ssrf(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "const express = require('express')\n"
        "const app = express()\n\n"
        "app.get('/users/:userId', (req, res) => res.json({}))\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert not any(f.check_id == "SSRF-001" for f in findings)


def test_fetch_with_literal_url_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "async function get() {\n"
        "  return fetch('https://api.example.com/data')\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert not any(f.check_id == "SSRF-001" for f in findings)


def test_axios_get_with_non_literal_url_is_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "const axios = require('axios')\n\n"
        "function proxy(targetUrl) {\n"
        "  return axios.get(targetUrl)\n"
        "}\n",
    )
    findings = detect_dangerous_sinks(tmp_path)
    assert any(f.check_id == "SSRF-001" for f in findings)
