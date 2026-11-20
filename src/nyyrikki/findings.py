"""Structured findings that keep observed evidence separate from interpretation.

Field order follows the Borealis output convention: what was observed, the rule's
assessment, the supporting evidence, a recommendation for a human, and (optionally)
a model's interpretation, which is always kept separate from the evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nyyrikki.events import Event

@dataclass
class Evidence:
    record_id: int
    event_id: int
    time_created: str
    computer: str
    fields: dict[str, str]

    @classmethod
    def from_event(cls, event: Event, field_names: tuple[str, ...]) -> "Evidence":
        return cls(
            record_id=event.record_id,
            event_id=event.event_id,
            time_created=event.time_created.isoformat(),
            computer=event.computer,
            fields={name: event.get(name) for name in field_names if name in event.data},
        )


@dataclass
class Finding:
    rule_id: str
    severity: str  # rule-assigned label (low/medium/high), not a probability
    observation: str  # what the events show, filled from event fields
    assessment: str  # the rule's fixed assessment
    evidence: list[Evidence]
    recommendation: str  # what a human should review; never executed
    limitations: str
    interpretation: str | None = None
    interpretation_rejected: str | None = None
    data_warnings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def record_ids(self) -> set[int]:
        return {item.record_id for item in self.evidence}
