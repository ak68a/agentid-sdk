#!/usr/bin/env python3
"""
AgentID Python Binding Demo

This script demonstrates basic usage of the AgentID Python bindings.
"""

import sys
# print(sys.path)

from agentid import PyAgent

def main():
    print("AgentID Python Demo")
    print("==================")

    # Create a new agent
    try:
        agent = PyAgent("demo-agent-123")
        print(f"\nCreated agent with ID: {agent.id}")

        # Try to create an agent with an invalid ID
        print("\nTrying to create agent with invalid ID...")
        invalid_agent = PyAgent("")  # This should raise an error
    except Exception as e:
        print(f"Error creating agent: {e}")

    print("\nDemo completed!")

if __name__ == "__main__":
    main() 