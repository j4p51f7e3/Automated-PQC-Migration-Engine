from typing import Protocol

class LLMClient(Protocol):
    def analyze(self, system_prompt: str, user_prompt: str) -> str:
        ...

import json

class MockLLMClient:
    def __init__(self):
        self.next_response = ""
        
    def analyze(self, system_prompt: str, user_prompt: str) -> str:
        if self.next_response:
            return self.next_response
            
        user_prompt_lower = user_prompt.lower()
        
        if "sign(" in user_prompt_lower or "sign_data" in user_prompt_lower:
            return json.dumps({
                "purpose": "Digital Signature",
                "confidence": "HIGH",
                "evidence": ["sign() is called in the source context"],
                "reasoning": "The explicit call to sign() indicates digital signature generation.",
                "manual_review_required": False
            })
            
        if "exchange(" in user_prompt_lower:
            return json.dumps({
                "purpose": "Key Agreement",
                "confidence": "HIGH",
                "evidence": ["exchange() is called in the source context"],
                "reasoning": "The context shows key agreement operations.",
                "manual_review_required": False
            })
            
        if "encrypt(" in user_prompt_lower:
            # RSA encryption for key transport is Key Establishment
            if "rsa" in user_prompt_lower:
                return json.dumps({
                    "purpose": "Key Establishment",
                    "confidence": "HIGH",
                    "evidence": ["encrypt() is called on an RSA key"],
                    "reasoning": "Explicit RSA encryption call indicating key transport.",
                    "manual_review_required": False
                })
            return json.dumps({
                "purpose": "Encryption",
                "confidence": "HIGH",
                "evidence": ["encrypt() is called"],
                "reasoning": "Explicit encryption call.",
                "manual_review_required": False
            })
            
        if "decrypt(" in user_prompt_lower:
            return json.dumps({
                "purpose": "Decryption",
                "confidence": "HIGH",
                "evidence": ["decrypt() is called"],
                "reasoning": "Explicit decryption call.",
                "manual_review_required": False
            })

        if "md5" in user_prompt_lower or "sha1" in user_prompt_lower:
            return json.dumps({
                "purpose": "Hashing",
                "confidence": "HIGH",
                "evidence": ["Hashing function called"],
                "reasoning": "This is a hashing operation, not a digital signature or encryption.",
                "manual_review_required": False
            })
            
        if "generate_private_key" in user_prompt_lower:
            return json.dumps({
                "purpose": "Unknown",
                "confidence": "LOW",
                "evidence": ["Only key generation is visible in context"],
                "reasoning": "Key generation alone does not reveal whether the key is used for signatures, encryption, or key establishment.",
                "manual_review_required": True
            })

        return json.dumps({
            "purpose": "Unknown",
            "confidence": "LOW",
            "evidence": [],
            "reasoning": "Not enough context to determine purpose.",
            "manual_review_required": True
        })
