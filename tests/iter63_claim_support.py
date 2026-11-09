"""Synthetic decision-B claim port for Gateway-only dispatcher tests.

Real claim semantics (versions, revocation order, expiry) are covered by the
Base core and SDK claim-port tests; Gateway tests only need a port that runs
the dispatcher's final validation and records claims.
"""

from __future__ import annotations


class SyntheticClaimPort:
    def __init__(self) -> None:
        self.claims = 0
        self.retired = 0
        self.validations = 0

    def ready(self) -> bool:
        return True

    def claim_native(self, record, identity, validate):
        validate(0)
        self.validations += 1
        self.claims += 1
        return ("synthetic-claim", record.reservation_id)

    def native_check(self, claim):
        return lambda: True

    def retire(self, claim) -> None:
        self.retired += 1


def claiming(native):
    """Wrap a synthetic native so it claims right after its marker commit.

    Legacy tests model "commit then native"; under decision B the native call
    must follow ``native_fence``. The proxy enters the fence immediately after
    a successful commit and leaves it when the synthetic native returns.
    """

    def wrapped(payload, port, scope):
        fences = []

        class Proxy:
            def __getattr__(self, name):
                return getattr(port, name)

            def commit(self, record):
                marker = port.commit(record)
                if marker is not None:
                    fence = port.native_fence()
                    check = fence.__enter__()
                    fences.append(fence)
                    check()
                return marker

        try:
            return native(payload, Proxy(), scope)
        finally:
            for fence in fences:
                fence.__exit__(None, None, None)

    return wrapped
