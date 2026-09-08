"""Adapters that put an agent runtime's tool call through the Interlock gateway.

One module per runtime. Nothing here is imported by the core: an adapter may depend on the
runtime's SDK, the core may not, so every such import is lazy and every runtime contract is
duck-typed. ``import agent_interlock`` must keep working with none of them installed.
"""
