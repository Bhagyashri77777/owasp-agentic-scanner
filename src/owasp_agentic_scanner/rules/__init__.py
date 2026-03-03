"""OWASP Agentic AI Top 10 detection rules."""

from owasp_agentic_scanner.rules.base import BaseRule, Finding, Severity
from owasp_agentic_scanner.rules.code_execution import CodeExecutionRule
from owasp_agentic_scanner.rules.excessive_agency import ExcessiveAgencyRule
from owasp_agentic_scanner.rules.goal_hijack import GoalHijackRule
from owasp_agentic_scanner.rules.insecure_plugin import InsecurePluginRule
from owasp_agentic_scanner.rules.memory_poisoning import MemoryPoisoningRule
from owasp_agentic_scanner.rules.model_theft import ModelTheftRule
from owasp_agentic_scanner.rules.overreliance import OverrelianceRule
from owasp_agentic_scanner.rules.privilege_abuse import PrivilegeAbuseRule
from owasp_agentic_scanner.rules.supply_chain import SupplyChainRule
from owasp_agentic_scanner.rules.tool_misuse import ToolMisuseRule

# Import AST-based rules (with fallback if not available)
try:
    from owasp_agentic_scanner.rules.code_execution_ast import CodeExecutionASTRule

    USE_AST_RULES = True
except ImportError:
    USE_AST_RULES = False

ALL_RULES: list[BaseRule] = [
    GoalHijackRule(),
    ToolMisuseRule(),
    PrivilegeAbuseRule(),
    SupplyChainRule(),
    CodeExecutionASTRule() if USE_AST_RULES else CodeExecutionRule(),  # Use AST if available
    MemoryPoisoningRule(),
    ExcessiveAgencyRule(),
    InsecurePluginRule(),
    OverrelianceRule(),
    ModelTheftRule(),
]

__all__ = [
    "ALL_RULES",
    "BaseRule",
    "CodeExecutionRule",
    "ExcessiveAgencyRule",
    "Finding",
    "GoalHijackRule",
    "InsecurePluginRule",
    "MemoryPoisoningRule",
    "ModelTheftRule",
    "OverrelianceRule",
    "PrivilegeAbuseRule",
    "Severity",
    "SupplyChainRule",
    "ToolMisuseRule",
]
