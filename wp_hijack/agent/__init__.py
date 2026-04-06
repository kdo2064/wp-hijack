"""
wp_hijack.agent — Autonomous AI pentesting agent module.
"""



from .agent_loop import AutonomousAgent

from .session import AgentSession, AgentStep

from .tool_runner import ToolResult, run_tool, run_python_exploit

from .tools import TOOL_REGISTRY, check_available, available_tools_block



__all__ = [

    "AutonomousAgent",

    "AgentSession",

    "AgentStep",

    "ToolResult",

    "run_tool",

    "run_python_exploit",

    "TOOL_REGISTRY",

    "check_available",

    "available_tools_block",

]
