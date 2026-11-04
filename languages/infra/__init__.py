"""Infrastructure-as-code "language" package: Terraform, GitLab CI, IAM/
resource policy JSON, shell wrapper scripts, and sensitive files committed to
the tree. Importing this triggers analyzer registration."""
from . import detector  # noqa: F401
from . import analyzers  # noqa: F401
