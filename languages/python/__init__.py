"""Python language package.

Importing this subpackage triggers registration of every framework
analyzer below via their @register decorators.
"""
from . import detector  # noqa: F401
from . import flask_analyzer  # noqa: F401
from . import fastapi_analyzer  # noqa: F401
from . import django_analyzer  # noqa: F401
