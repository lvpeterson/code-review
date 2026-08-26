"""Language + framework detection for JavaScript/TypeScript targets."""
from __future__ import annotations

import json
from pathlib import Path

from core.fsutil import any_file_exists, iter_files, read_text_safe


def detect_language(target_path: Path) -> bool:
    if any_file_exists(target_path, "package.json"):
        return True
    return any(True for _ in iter_files(target_path, (".js", ".ts")))


def detect_frameworks(target_path: Path) -> list[str]:
    """Return every framework detected: "express" and/or "nextjs".

    TODO: add detect for other JS frameworks (NestJS, Koa, Hapi, Fastify) --
    follow the same pattern as express below.
    """
    found: set[str] = set()

    package_json = target_path / "package.json"
    if package_json.exists():
        try:
            data = json.loads(read_text_safe(package_json) or "{}")
        except json.JSONDecodeError:
            data = {}
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        if "express" in deps:
            found.add("express")
        if "next" in deps:
            found.add("nextjs")

    if any_file_exists(target_path, "next.config.js", "next.config.mjs", "next.config.ts"):
        found.add("nextjs")

    if found:
        return sorted(found)

    for src_file in iter_files(target_path, (".js", ".ts")):
        text = read_text_safe(src_file)
        if "require('express')" in text or 'require("express")' in text or "from 'express'" in text or 'from "express"' in text:
            found.add("express")

    return sorted(found)
