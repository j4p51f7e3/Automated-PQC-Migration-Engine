import json
from scanner.models import SecurityFinding

SYSTEM_PROMPT = """You are an expert cryptographic security code analyzer.
Your task is to determine the semantic purpose of a cryptographic operation based ONLY on its algorithm, API, and supplied source context.

CRITICAL INSTRUCTIONS:
- Analyze ONLY the supplied source context.
- Do not assume an operation that is not shown in the source context.
- Do not infer "Digital Signature" merely because RSA or ECC is detected.
- Key generation alone is insufficient to determine semantic purpose. If you only see key generation, return "Unknown".
- Look for concrete operations such as: sign(), verify(), encrypt(), decrypt(), exchange(), ECDH, ECDSA, and hashing functions.
- If the evidence is insufficient to determine the purpose, return "Unknown" with "LOW" confidence.
- Evidence MUST be grounded in the exact source supplied. Do not invent API calls, function calls, variables, or behavior.

You MUST respond ONLY with a JSON object. Do not include any markdown formatting like ```json.
The JSON object must have exactly five fields:
1. "purpose": Must be exactly one of: ["Key Establishment", "Key Agreement", "Digital Signature", "Encryption", "Decryption", "Authentication", "Hashing", "Other", "Unknown"]
2. "confidence": Must be exactly one of: ["HIGH", "MEDIUM", "LOW"]
3. "evidence": A list of strings. Extract specific evidence from the source code that supports your classification. Do not invent evidence not present in the source context.
4. "reasoning": A concise string explanation of why the detected code was classified as the selected semantic purpose.
5. "manual_review_required": A boolean indicating if manual review is needed.

Example output:
{
  "purpose": "Digital Signature",
  "confidence": "HIGH",
  "evidence": [
    "private_key.sign() is called at line 12",
    "The resulting value is stored in the signature variable"
  ],
  "reasoning": "The RSA private key is explicitly used to generate a digital signature.",
  "manual_review_required": false
}
"""

def build_analysis_prompt(finding: SecurityFinding) -> str:
    prompt = "Analyze the following cryptographic usage:\n\n"
    prompt += f"Algorithm: {finding.algorithm}\n"
    prompt += f"API/Library: {finding.detected_api}\n"
    prompt += f"Usage Category: {finding.usage}\n"
    
    if finding.function_name:
        prompt += f"Function Name: {finding.function_name}\n"
        
    if finding.source_context:
        prompt += f"\nSource Context:\n{finding.source_context.strip()}\n"
        
    return prompt
