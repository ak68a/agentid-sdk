# AgentID Python Bindings

Python bindings for the AgentID SDK using PyO3.

## Prerequisites

- Python 3.7 or later
- Rust toolchain (rustc, cargo)
- setuptools_rust (for building Rust extensions)

## Development Setup

1. Create and activate a virtual environment:
```bash
python -m venv venv # Run on root level of the repo (agentid-sdk)
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
```

2. Install build dependencies:
```bash
pip install --upgrade pip setuptools wheel
pip install setuptools_rust
```

3. Install the package in development mode:
```bash
pip install -e .
```

## Building for Distribution

```bash
python -m build
```

This will create a wheel file in the `dist/` directory.

## Testing

```bash
pytest
```

## Notes
- Make sure you have Rust installed and up to date
- The `setuptools_rust` package is required for building the Rust extensions
- If you get build errors, try updating Rust: `rustup update`

## Usage

### Basic Example

```python
from agentid import PyAgent

# Create a new agent
agent = PyAgent("my-agent")

# Get the agent's ID
print(agent.id)  # prints: my-agent
```

### Error Handling

The bindings use Python's native exception system:

```python
from agentid import PyAgent

try:
    # This will raise ValueError if the agent ID is invalid
    agent = PyAgent("invalid/id/with/slashes")
except ValueError as e:
    print(f"Failed to create agent: {e}")
```

## API Reference

### PyAgent

The main class representing an AgentID agent.

#### Constructor

```python
PyAgent(id: str) -> PyAgent
```

Creates a new agent with the given ID.

- `id`: A string identifier for the agent. Must be a valid agent ID format.
- Returns: A new `PyAgent` instance
- Raises: `ValueError` if the ID is invalid

#### Properties

- `id`: (str) The agent's identifier

## Development

### Building

To build the package:

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

### Adding New Features

When adding new features to the Python bindings:

1. Add the feature to the Rust SDK first
2. Create Python bindings in `src/lib.rs`
3. Add Python-style documentation
4. Add tests
5. Update this README

## Examples

### Creating and Using Agents

```python
from agentid import PyAgent

# Create multiple agents
agent1 = PyAgent("agent-1")
agent2 = PyAgent("agent-2")

# Use in a list
agents = [PyAgent(f"agent-{i}") for i in range(3)]

# Print agent IDs
for agent in agents:
    print(f"Agent ID: {agent.id}")
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Update documentation
6. Submit a pull request

## License

Apache License 2.0 
Apache License 2.0 