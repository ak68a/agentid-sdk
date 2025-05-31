# AgentID Python Demo

This is a simple demo project showing how to use the AgentID Python bindings.

## Prerequisites

- Python 3.7 or later
- Rust toolchain (rustc, cargo)
- setuptools_rust (for building Rust extensions)

## Setup

1. Create and activate a virtual environment:
```bash
# Create a new virtual environment
python -m venv venv

# Activate the virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
# .\venv\Scripts\activate

# Verify you're using the virtual environment
which python  # Should point to the venv directory
```

2. Install build dependencies:
```bash
# Upgrade pip and install build tools
pip install --upgrade pip setuptools wheel
pip install setuptools_rust
```

3. Install the AgentID Python package in development mode:
```bash
cd agentid-sdk/bindings/python
pip install -e .
```

4. Install the demo requirements:
```bash
cd agentid-sdk/examples/python
pip install -r requirements.txt
```

## Running the Demo

Make sure your virtual environment is activated, then:
```bash
python demo.py
```

This will:
1. Create a new agent
2. Print the agent's ID
3. Demonstrate basic error handling

## Troubleshooting

If you encounter build errors:
1. Make sure Rust is installed and up to date: `rustup update`
2. Verify setuptools_rust is installed: `pip list | grep setuptools-rust`
3. Try cleaning and rebuilding: `pip uninstall agentid-python && pip install -e .`

## Deactivating the Virtual Environment

When you're done, you can deactivate the virtual environment:
```bash
deactivate
```

## Notes
- Always activate the virtual environment before running the demo
- The virtual environment should be recreated if you switch Python versions
- Add `venv/` to your `.gitignore` if you're using version control 