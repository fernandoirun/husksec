"""husksec (CSI::nano) - a tiny, scope-enforced security layer over the husk kernel.

Legitimate use only: authorized targets, legal practice ranges (public CTFs,
labs, your own systems), and responsible disclosure. The authorization boundary
is :class:`husksec.scope.Scope`; nothing acts on a target it does not allow.
"""
from .scope import Scope, ScopeError, normalize_target, matches

__version__ = "0.1.0"
__all__ = ["Scope", "ScopeError", "normalize_target", "matches", "__version__"]
