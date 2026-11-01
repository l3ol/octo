"""Enter the unprivileged mount namespace before any test or fixture runs."""

from gates.readonly_ns import ensure_harness_namespace

ensure_harness_namespace()
