# Personas

## the-ml-platform-lead-who-refuses-k8s

Runs self-hosted models on a rack. Wants a runtime in a box next door that dynamically allocates real services: a tenant key forks a real HTTP server in a hardware-isolated microVM, warm in tens of milliseconds, reaped when idle. No k8s, no other infra stack.

## cloud-native-agent-team-needing-egress-governance

The model endpoint is just an upstream (a local rack or api.openai.com, same config shape). Agents reach only what is allowlisted; a prompt-injected exfiltration attempt dies at the egress wall with a journal line; every provider call is metered per consumer.

## reverse-proxy-operator

Still first-class: swerver is a fast, correct HTTP/1/2/3 reverse proxy with TLS termination, routing, and a full middleware chain, usable with none of the agent-compute machinery.
