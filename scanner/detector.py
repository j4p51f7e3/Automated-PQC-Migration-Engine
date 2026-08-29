import ast

from scanner.models import SecurityFinding
from scanner.rules import CRYPTO_RULES


class CryptoDetector(ast.NodeVisitor):

    def __init__(self, file_path):
        self.file_path = file_path
        self.findings = []
        self.imports = {}
        
        self.file_lines = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.file_lines = f.readlines()
        except Exception:
            pass

    # =========================================================
    # IMPORT HANDLING
    # =========================================================

    def visit_Import(self, node):

        for alias in node.names:

            name = alias.name

            local_name = (
                alias.asname
                if alias.asname
                else name
            )

            self.imports[local_name] = name

        self.generic_visit(node)

    def visit_ImportFrom(self, node):

        module = node.module

        if module:

            for alias in node.names:

                full_name = f"{module}.{alias.name}"

                local_name = (
                    alias.asname
                    if alias.asname
                    else alias.name
                )

                self.imports[local_name] = full_name

        self.generic_visit(node)

    # =========================================================
    # FUNCTION CALL DETECTION
    # =========================================================

    def visit_Call(self, node):

        function_name = self.get_function_name(node)

        resolved_name = self.resolve_import(function_name)

        rule = self.find_rule(
            function_name,
            resolved_name
        )

        # -----------------------------------------------------
        # Ignore ECC curve constructors
        # -----------------------------------------------------

        if self.is_ecc_curve(function_name, resolved_name):
            self.generic_visit(node)
            return

        if rule:

            usage = self.determine_usage(
                function_name
            )

            key_size = self.get_rsa_key_size(
                node,
                function_name
            )

            curve = self.get_ecc_curve(
                node,
                function_name
            )

            start_line = max(0, node.lineno - 3)
            end_line = min(len(self.file_lines), node.lineno + 10)
            context_lines = self.file_lines[start_line:end_line]
            source_context = "".join(context_lines).strip()

            finding = SecurityFinding(
                rule_id=rule["rule_id"],
                file=self.file_path,
                line=node.lineno,
                column=node.col_offset,
                algorithm=rule["algorithm"],
                category=rule["category"],
                severity=rule["severity"],
                description=rule["description"],
                recommendation=rule["recommendation"],
                detected_api=(
                    resolved_name
                    if resolved_name
                    else function_name
                ),
                usage=usage,
                key_size=key_size,
                curve=curve,
                function_name=function_name,
                source_context=source_context
            )

            self.findings.append(finding)

        self.generic_visit(node)

    # =========================================================
    # GET FUNCTION NAME
    # =========================================================

    @staticmethod
    def get_function_name(node):

        if isinstance(node.func, ast.Attribute):

            parts = []

            current = node.func

            while isinstance(current, ast.Attribute):

                parts.append(current.attr)

                current = current.value

            if isinstance(current, ast.Name):

                parts.append(current.id)

            parts.reverse()

            return ".".join(parts)

        elif isinstance(node.func, ast.Name):

            return node.func.id

        return None

    # =========================================================
    # RESOLVE IMPORT
    # =========================================================

    def resolve_import(self, function_name):

        if not function_name:
            return None

        parts = function_name.split(".")

        first_part = parts[0]

        if first_part not in self.imports:

            return function_name

        resolved = self.imports[first_part]

        if len(parts) > 1:

            resolved += "." + ".".join(parts[1:])

        return resolved

    # =========================================================
    # FIND SECURITY RULE
    # =========================================================

    def find_rule(
        self,
        function_name,
        resolved_name
    ):

        candidates = [
            function_name,
            resolved_name
        ]

        for candidate in candidates:

            if candidate in CRYPTO_RULES:

                return CRYPTO_RULES[candidate]

        if resolved_name:

            if resolved_name.startswith(
                "cryptography.hazmat.primitives.asymmetric.rsa"
            ):

                return CRYPTO_RULES[
                    "cryptography.hazmat.primitives.asymmetric.rsa"
                ]

            if resolved_name.startswith(
                "cryptography.hazmat.primitives.asymmetric.ec"
            ):

                return CRYPTO_RULES[
                    "cryptography.hazmat.primitives.asymmetric.ec"
                ]

        return None

    # =========================================================
    # ECC CURVE DETECTION
    # =========================================================

    @staticmethod
    def is_ecc_curve(
        function_name,
        resolved_name
    ):

        name = (
            resolved_name
            if resolved_name
            else function_name
        )

        if not name:
            return False

        curves = [
            "SECP192R1",
            "SECP224R1",
            "SECP256R1",
            "SECP384R1",
            "SECP521R1",
            "SECP256K1",
            "SECT163K1",
            "SECT233K1",
            "SECT283K1",
            "SECT409K1",
            "SECT571K1"
        ]

        return any(
            name.endswith("." + curve)
            for curve in curves
        )

    # =========================================================
    # GET ECC CURVE
    # =========================================================

    @staticmethod
    def get_ecc_curve(
        node,
        function_name
    ):

        if function_name != "ec.generate_private_key":

            return None

        if not node.args:

            return None

        curve_node = node.args[0]

        if isinstance(
            curve_node,
            ast.Call
        ):

            curve_name = CryptoDetector.get_function_name(
                curve_node
            )

            if curve_name:

                return curve_name.split(".")[-1]

        return None

    # =========================================================
    # RSA KEY SIZE
    # =========================================================

    @staticmethod
    def get_rsa_key_size(
        node,
        function_name
    ):

        if function_name != "rsa.generate_private_key":

            return None

        for keyword in node.keywords:

            if keyword.arg == "key_size":

                if isinstance(
                    keyword.value,
                    ast.Constant
                ):

                    if isinstance(
                        keyword.value.value,
                        int
                    ):

                        return keyword.value.value

        return None

    # =========================================================
    # DETERMINE USAGE
    # =========================================================

    @staticmethod
    def determine_usage(
        function_name
    ):

        if not function_name:

            return "Unknown"

        name = function_name.lower()

        # RSA

        if "rsa.generate_private_key" in name:

            return "Key Generation"

        if "rsa" in name:

            if "encrypt" in name:
                return "Encryption"

            if "decrypt" in name:
                return "Decryption"

            if "sign" in name:
                return "Digital Signature"

        # ECC

        if "ec.generate_private_key" in name:

            return "Key Generation"

        if "exchange" in name:

            return "Key Agreement"

        if "sign" in name:

            return "Digital Signature"

        # Hashes

        if "md5" in name:

            return "Hashing"

        if "sha1" in name:

            return "Hashing"

        return "Unknown"


def detect_crypto(
    file_path,
    tree
):

    detector = CryptoDetector(
        file_path
    )

    detector.visit(tree)

    return detector.findings