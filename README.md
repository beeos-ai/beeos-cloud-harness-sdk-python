# BeeOS Cloud Harness SDK for Python

Python SDK for connecting custom agent harnesses to BeeOS Cloud. It provides
runtime registration and lease management, signed agent requests, durable
command delivery, and chat reply handling.

## Installation

Requires Python 3.11 or later.

```sh
pip install beeos-cloud-harness-sdk
```

## Usage

```python
from beeos_cloud_harness_sdk import RUNTIME_METHODS, operation_path

print(RUNTIME_METHODS)
print(operation_path("agentGet", agentId="your-agent-id"))
```

`BeeOSAgentRuntime` connects a harness to the configured Agent Gateway and
Message Service using its runtime lease. The `identity`, `registration`,
`lease_http`, and `runtime_delivery_port` modules provide the building blocks
for managing identity, authority, and delivery. Keep private signing keys with
the harness; use the Cloud-issued lease credentials for runtime requests.

Source and issues: [beeos-cloud-harness-sdk-python](https://github.com/beeos-ai/beeos-cloud-harness-sdk-python).

## License

MIT. See [LICENSE](LICENSE).
