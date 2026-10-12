"""Provider-neutral durable command routing for a shared account gateway."""

from .event_journal import (
    GatewayAccountEvent,
    GatewayAccountSnapshot,
    GatewayEventJournal,
    GatewayEventJournalError,
    GatewayReadBatch,
)
from .resolution import (
    GatewayActionResolution,
    GatewayProviderBinding,
    GatewayProviderQueryProof,
    GatewayQueryVerifier,
    GatewayResolutionCapability,
    GatewayResolutionRequest,
)
from .router import (
    GatewayAdmission,
    GatewayCommand,
    GatewayCommandKind,
    GatewayCommandRouter,
    GatewayCommandStatus,
    GatewayDispatchError,
    GatewayDispatchResult,
    GatewayExecutor,
    GatewayPrincipal,
    GatewayRoutingError,
)
from .wire_mapping import (
    GATEWAY_COMMAND_WIRE_SCHEMA,
    GatewayWireMappingError,
    gateway_command_from_wire_payload,
    gateway_command_to_wire_payload,
)
from .writer_authority import (
    GatewayAccountWriterAuthority,
    GatewayActionClaim,
    GatewayActionRecord,
    GatewayActionStatus,
    GatewayWriterAuthorityError,
    GatewayWriterLease,
)

__all__ = [
    "GatewayAccountEvent",
    "GatewayAccountSnapshot",
    "GatewayAccountWriterAuthority",
    "GatewayActionClaim",
    "GatewayActionRecord",
    "GatewayActionResolution",
    "GatewayActionStatus",
    "GatewayAdmission",
    "GatewayCommand",
    "GatewayCommandKind",
    "GatewayCommandRouter",
    "GatewayCommandStatus",
    "GatewayDispatchError",
    "GatewayDispatchResult",
    "GatewayEventJournal",
    "GatewayEventJournalError",
    "GatewayExecutor",
    "GatewayPrincipal",
    "GatewayProviderBinding",
    "GatewayProviderQueryProof",
    "GatewayQueryVerifier",
    "GatewayResolutionCapability",
    "GatewayResolutionRequest",
    "GatewayReadBatch",
    "GatewayRoutingError",
    "GATEWAY_COMMAND_WIRE_SCHEMA",
    "GatewayWireMappingError",
    "GatewayWriterAuthorityError",
    "GatewayWriterLease",
    "gateway_command_from_wire_payload",
    "gateway_command_to_wire_payload",
]
