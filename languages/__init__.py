"""All supported languages.

Importing this package imports every language subpackage, which in turn
imports every framework analyzer -- populating core.registry before
enumerator.py runs. To add support for a new language:

  1. Create languages/<newlang>/ with detector.py + __init__.py
  2. Add one <framework>_analyzer.py per framework, each registering itself
     with @registry.register("<newlang>", "<framework>")
  3. Import it below, and add it to enumerator.LANGUAGE_MODULES
"""
from . import python  # noqa: F401
from . import java  # noqa: F401
from . import javascript  # noqa: F401
from . import go  # noqa: F401
from . import ruby  # noqa: F401
from . import dotnet  # noqa: F401
