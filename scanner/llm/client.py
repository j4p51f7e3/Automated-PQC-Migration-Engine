from typing import Protocol

class LLMClient(Protocol):
    def analyze(self, system_prompt: str, user_prompt: str) -> str:
        ...

import json

class MockLLMClient:
    def __init__(self):
        self.next_response = ""
        
    def analyze(self, system_prompt: str, user_prompt: str) -> str:
        return self.next_response
