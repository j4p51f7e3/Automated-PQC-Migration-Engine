from dataclasses import dataclass


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
    key_size: int = None
    curve: str = None

    def display(self):

        print("-" * 60)

        print(f"File           : {self.file}")
        print(f"Line           : {self.line}")
        print(f"Algorithm      : {self.algorithm}")
        print(f"Usage          : {self.usage}")

        if self.key_size:
            print(f"Key Size       : {self.key_size}")

        if self.curve:
            print(f"Curve          : {self.curve}")

        print(f"Severity       : {self.severity}")
        print(f"Category       : {self.category}")
        print(f"Detected API   : {self.detected_api}")

        print()
        print("Reason:")
        print(self.description)

        print()
        print("Recommendation:")
        print(self.recommendation)

        print("-" * 60)