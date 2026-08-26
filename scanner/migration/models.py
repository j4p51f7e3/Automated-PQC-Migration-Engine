from dataclasses import dataclass, asdict
from typing import List, Optional


@dataclass
class MigrationResult:
    algorithm: str
    original_usage: str
    migration_type: str
    primary_replacement: Optional[str]
    alternative_replacements: List[str]
    manual_review_required: bool
    reason: Optional[str] = None

    def to_dict(self):
        return asdict(self)
