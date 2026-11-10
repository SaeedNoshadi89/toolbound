"""Optional provider adapters.

Each adapter converts Toolbound definitions to a provider's tool format and runs
the provider's tool calls through the Gateway. None of them import a provider
SDK, and none contain security logic: everything is enforced by the core.

* :mod:`toolbound.adapters.anthropic` - Anthropic Messages API
* :mod:`toolbound.adapters.openai` - OpenAI Chat Completions and Responses APIs
"""
