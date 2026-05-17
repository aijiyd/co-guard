"""Shared runtime primitives for local multi-agent execution."""

from .runtime import BaseLocalAgentRuntime, build_local_agent_runtime

__all__ = ["BaseLocalAgentRuntime", "build_local_agent_runtime"]
