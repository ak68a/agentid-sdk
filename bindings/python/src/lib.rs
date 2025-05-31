use agentid_core::Agent;
use anyhow::Result;
use pyo3::prelude::*;

/// A Python class representing an AgentID agent
#[pyclass]
struct PyAgent {
    agent: Agent,
}

#[pymethods]
impl PyAgent {
    /// Create a new agent with the given ID
    #[new]
    fn new(id: &str) -> PyResult<Self> {
        let agent = Agent::new(id)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Ok(Self { agent })
    }

    /// Get the agent's ID
    #[getter]
    fn id(&self) -> String {
        self.agent.id().to_string()
    }
}

/// Python module for AgentID SDK
#[pymodule]
fn agentid(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyAgent>()?;
    Ok(())
}
