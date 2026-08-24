from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class SecurityFinding:
    rule_id: str
    file: str
    line: int
    column: int
    algorithm: str
    category: str
    severity: str
    description: str
    recommendation: str
    detected_api: str
    usage: str = "Unknown"
    key_size: Optional[int] = None
    curve: Optional[str] = None
    function_name: Optional[str] = None
    source_context: Optional[str] = None

    def to_dict(self):
        return asdict(self)

    def display(self):
        print("-" * 60)
        print(f"File           : {self.file}")
        print(f"Line           : {self.line}")
        
        if self.function_name:
            print(f"Function       : {self.function_name}")
            
        print(f"Algorithm      : {self.algorithm}")
        print(f"Usage          : {self.usage}")

        if self.key_size:
            print(f"Key Size       : {self.key_size}")

        if self.curve:
            print(f"Curve          : {self.curve}")

        print(f"Severity       : {self.severity}")
        print(f"Category       : {self.category}")
        print(f"Detected API   : {self.detected_api}")

        if self.source_context:
            print()
            print("Context:")
            print(self.source_context.rstrip())

        print()
        print("Reason:")
        print(self.description)

        print()
        print("Recommendation:")
        print(self.recommendation)
        print("-" * 60)