from typing import Optional

from scanner.models import SecurityFinding
from scanner.migration.models import MigrationResult
from scanner.migration.rules import MIGRATION_RULES


class MigrationAnalyzer:
    """
    Analyzes SecurityFindings and determines deterministic migration paths.
    """
    
    @staticmethod
    def analyze(finding: SecurityFinding) -> Optional[MigrationResult]:
        """
        Takes a SecurityFinding and returns the recommended MigrationResult.
        If no rule matches, returns None.
        """
        if not finding.algorithm or not finding.usage:
            return None
            
        rule_key = f"{finding.algorithm}:{finding.usage}"
        
        # Check for specific rule
        rule_data = MIGRATION_RULES.get(rule_key)
        
        # Fallback to unknown usage rule for the algorithm if specific rule doesn't exist
        if not rule_data:
            fallback_key = f"{finding.algorithm}:Unknown"
            rule_data = MIGRATION_RULES.get(fallback_key)
            
        if not rule_data:
            return None
            
        return MigrationResult(
            algorithm=finding.algorithm,
            original_usage=finding.usage,
            migration_type=rule_data["migration_type"],
            primary_replacement=rule_data.get("primary_replacement"),
            alternative_replacements=rule_data.get("alternative_replacements", []),
            manual_review_required=rule_data.get("manual_review_required", True),
            reason=rule_data.get("reason")
        )
