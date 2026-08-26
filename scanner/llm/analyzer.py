import json
from scanner.models import SecurityFinding
from scanner.llm.client import LLMClient
from scanner.llm.models import AnalysisResult, SemanticPurpose, ConfidenceLevel
from scanner.llm.prompts import SYSTEM_PROMPT, build_analysis_prompt

class LLMAnalyzer:
    def __init__(self, client: LLMClient):
        self.client = client

    def analyze_finding(self, finding: SecurityFinding) -> AnalysisResult:
        user_prompt = build_analysis_prompt(finding)
        
        fallback_result = AnalysisResult(
            purpose=SemanticPurpose.UNKNOWN,
            confidence=ConfidenceLevel.LOW,
            evidence=[],
            reasoning="Unable to reliably determine the cryptographic purpose.",
            manual_review_required=True,
            raw_response=""
        )

        try:
            response_text = self.client.analyze(SYSTEM_PROMPT, user_prompt)
            fallback_result.raw_response = response_text
            
            # Try parsing as JSON
            data = json.loads(response_text)
            
            # Extract fields
            purpose_str = data.get("purpose")
            confidence_str = data.get("confidence")
            evidence = data.get("evidence")
            reasoning = data.get("reasoning")
            manual_review = data.get("manual_review_required")
            
            # Validate types and missing fields
            if purpose_str is None or confidence_str is None or reasoning is None or manual_review is None:
                return fallback_result
                
            if not isinstance(evidence, list):
                return fallback_result
                
            # Map strings to Enums, fallback to ValueError if invalid
            purpose = SemanticPurpose(purpose_str)
            confidence = ConfidenceLevel(confidence_str)
            
            # Additional validation logic for manual review
            if purpose == SemanticPurpose.UNKNOWN or confidence == ConfidenceLevel.LOW:
                manual_review = True
                
            return AnalysisResult(
                purpose=purpose,
                confidence=confidence,
                evidence=evidence,
                reasoning=str(reasoning),
                manual_review_required=bool(manual_review),
                raw_response=response_text
            )
            
        except (json.JSONDecodeError, ValueError, KeyError):
            # If JSON is malformed, or if purpose/confidence aren't valid enum values
            return fallback_result
