import ast


def parse_file(file_path):
    """
    Read a Python file and convert it into an Abstract Syntax Tree.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        source_code = file.read()

    try:
        tree = ast.parse(source_code, filename=file_path)
        return tree

    except SyntaxError as error:
        print(f"[ERROR] Could not parse {file_path}")
        print(f"        {error}")
        return None