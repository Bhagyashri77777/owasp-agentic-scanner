"""Sample code with various security vulnerabilities for testing the scanner.

This file demonstrates the different types of issues the OWASP Agentic AI
Scanner can detect using its new AST-based analysis.
"""

import os
import pickle
import subprocess
import sys

# AA05: Unexpected Code Execution Examples


def vulnerable_eval_example():
    """CRITICAL: eval() with user input - will be detected with HIGH confidence."""
    user_input = input("Enter Python expression: ")
    result = eval(user_input)  # noqa: S307 - Intentional vulnerability for testing
    return result


def safe_eval_example():
    """OK: Using safe alternative - will NOT be flagged."""
    import ast

    data = '{"key": "value"}'
    result = ast.literal_eval(data)  # Safe!
    return result


def hardcoded_eval_example():
    """MEDIUM confidence: eval() without obvious taint."""
    expression = "2 + 2"
    result = eval(expression)  # noqa: S307 - Intentional vulnerability for testing
    return result


def exec_with_llm_output():
    """CRITICAL: Executing LLM-generated code - NEW detection pattern."""
    llm_response = call_openai_api("Generate Python code")
    exec(llm_response)  # noqa: S102 - Intentional vulnerability for testing


def command_injection_vulnerable():
    """CRITICAL: subprocess with shell=True and user input."""
    user_command = sys.argv[1]
    subprocess.run(user_command, shell=True)  # noqa: S602 - Intentional vulnerability for testing


def command_injection_safe():
    """OK: subprocess with proper argument list - will NOT be flagged."""
    subprocess.run(["ls", "-la"])  # Safe!


def os_system_dangerous():
    """CRITICAL: os.system() usage detected."""
    filename = input("Enter filename: ")
    os.system(f"cat {filename}")  # noqa: S605 - Intentional vulnerability for testing


def pickle_unsafe():
    """HIGH: Unsafe deserialization."""
    untrusted_data = receive_from_network()
    obj = pickle.loads(untrusted_data)  # noqa: S301 - Intentional vulnerability for testing
    return obj


def suppressed_eval():
    """This eval is intentionally allowed via inline suppression."""
    # Used for testing calculator feature with controlled input
    result = eval("2 + 2")  # noqa: S307 - Intentional for testing suppression
    return result


def taint_propagation_example():
    """Demonstrates taint tracking through variables."""
    user_input = input("Enter: ")
    temp_var = user_input
    another_var = temp_var
    eval(another_var)  # noqa: S307 - Intentional vulnerability for testing


def f_string_taint_example():
    """Demonstrates taint tracking through f-strings."""
    user_name = input("Name: ")
    command = f"echo {user_name}"
    os.system(command)  # noqa: S605 - Intentional vulnerability for testing


# Helper functions (not real implementations)
def call_openai_api(prompt: str) -> str:  # noqa: ARG001
    """Dummy function."""
    return "print('generated code')"


def receive_from_network() -> bytes:
    """Dummy function."""
    return b"data"


if __name__ == "__main__":
    # Running this code is dangerous! It's for testing the scanner only.
    print("This file is for scanner testing only!")
    print("Do NOT run this code - it contains intentional vulnerabilities!")
