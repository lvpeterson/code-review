"""Language + framework detection for Java targets."""
from __future__ import annotations

from pathlib import Path

from core.fsutil import any_file_exists, iter_files, read_text_safe

_LANGUAGE_SIGNAL_FILES = ("pom.xml", "build.gradle", "build.gradle.kts")


def detect_language(target_path: Path) -> bool:
    if any_file_exists(target_path, *_LANGUAGE_SIGNAL_FILES):
        return True
    return any(True for _ in iter_files(target_path, (".java",)))


def detect_frameworks(target_path: Path) -> list[str]:
    """Return every framework detected -- currently just ["spring"] or [].

    TODO: add detect for other Java frameworks as needed (Struts, JAX-RS/
    Jersey, Micronaut, Quarkus) -- follow the same pattern as spring below.
    """
    manifest_text = ""
    for name in _LANGUAGE_SIGNAL_FILES:
        manifest_text += read_text_safe(target_path / name).lower()

    if "spring-boot" in manifest_text or "springframework" in manifest_text:
        return ["spring"]

    for java_file in iter_files(target_path, (".java",)):
        text = read_text_safe(java_file)
        if "org.springframework" in text or "@SpringBootApplication" in text:
            return ["spring"]

    return []
