//! Host functions exposed to WASM plugins

use crate::{PluginError, PluginMetadata, PluginOutput};
use anyhow::Result;
use rma_common::{Finding, Language};
use wasmtime::{Caller, Engine, Instance, Linker, Store};

/// State held by the host for plugin execution
pub struct HostState {
    /// Memory for passing data to/from plugins
    input_buffer: Vec<u8>,
    output_buffer: Vec<u8>,
}

impl HostState {
    pub fn new() -> Self {
        Self {
            input_buffer: Vec::with_capacity(1024 * 1024), // 1MB
            output_buffer: Vec::with_capacity(1024 * 1024),
        }
    }

    pub fn set_input(&mut self, data: &[u8]) {
        self.input_buffer.clear();
        self.input_buffer.extend_from_slice(data);
    }

    pub fn get_output(&self) -> &[u8] {
        &self.output_buffer
    }
}

impl Default for HostState {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a linker with host functions for plugins
pub fn create_linker(engine: &Engine) -> Result<Linker<HostState>> {
    let mut linker = Linker::new(engine);

    // Host function: get input length
    linker.func_wrap(
        "env",
        "rma_get_input_len",
        |caller: Caller<'_, HostState>| -> i32 { caller.data().input_buffer.len() as i32 },
    )?;

    // Host function: read input into plugin memory
    linker.func_wrap(
        "env",
        "rma_read_input",
        |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
            let memory = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(mem)) => mem,
                _ => return -1,
            };

            // Copy input buffer to avoid borrow conflict
            let input_len = caller.data().input_buffer.len();
            let len = (len as usize).min(input_len);
            let input_data: Vec<u8> = caller.data().input_buffer[..len].to_vec();

            if memory
                .write(&mut caller, ptr as usize, &input_data)
                .is_err()
            {
                return -1;
            }

            len as i32
        },
    )?;

    // Host function: write output from plugin memory
    linker.func_wrap(
        "env",
        "rma_write_output",
        |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
            let memory = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(mem)) => mem,
                _ => return -1,
            };

            let mut buffer = vec![0u8; len as usize];
            if memory.read(&caller, ptr as usize, &mut buffer).is_err() {
                return -1;
            }

            caller.data_mut().output_buffer = buffer;
            0
        },
    )?;

    // Host function: log from plugin
    linker.func_wrap(
        "env",
        "rma_log",
        |mut caller: Caller<'_, HostState>, level: i32, ptr: i32, len: i32| {
            let memory = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(mem)) => mem,
                _ => return,
            };

            let mut buffer = vec![0u8; len as usize];
            if memory.read(&caller, ptr as usize, &mut buffer).is_ok()
                && let Ok(msg) = String::from_utf8(buffer)
            {
                match level {
                    0 => tracing::error!(target: "plugin", "{}", msg),
                    1 => tracing::warn!(target: "plugin", "{}", msg),
                    2 => tracing::info!(target: "plugin", "{}", msg),
                    _ => tracing::debug!(target: "plugin", "{}", msg),
                }
            }
        },
    )?;

    Ok(linker)
}

/// Get plugin metadata by calling the plugin's get_metadata export
pub fn get_plugin_metadata(
    store: &mut Store<HostState>,
    instance: &Instance,
) -> Result<PluginMetadata, PluginError> {
    // Try to get the metadata export
    let get_metadata = instance
        .get_typed_func::<(), i32>(&mut *store, "rma_get_metadata")
        .map_err(|_| PluginError::InterfaceError("Missing rma_get_metadata export".into()))?;

    // Call to populate output buffer
    get_metadata
        .call(&mut *store, ())
        .map_err(|e| PluginError::ExecutionError(format!("get_metadata failed: {}", e)))?;

    // Parse metadata from output buffer
    let output = store.data().get_output();
    let metadata: PluginMetadata = serde_json::from_slice(output)
        .map_err(|e| PluginError::InterfaceError(format!("Invalid metadata JSON: {}", e)))?;

    Ok(metadata)
}

/// Call the plugin's analyze function
pub fn call_analyze(
    store: &mut Store<HostState>,
    instance: &Instance,
    source: &str,
    language: Language,
) -> Result<Vec<Finding>> {
    // Prepare input
    let input = crate::PluginInput {
        source: source.to_string(),
        file_path: String::new(),
        language: language.to_string(),
    };
    let input_json = serde_json::to_vec(&input)?;
    store.data_mut().set_input(&input_json);

    // Get and call analyze function
    let analyze = instance
        .get_typed_func::<(), i32>(&mut *store, "rma_analyze")
        .map_err(|_| anyhow::anyhow!("Missing rma_analyze export"))?;

    let result = analyze.call(&mut *store, ())?;

    if result != 0 {
        return Err(anyhow::anyhow!(
            "Plugin analysis returned error code: {}",
            result
        ));
    }

    // Parse output
    let output = store.data().get_output();
    let plugin_output: PluginOutput = serde_json::from_slice(output)?;

    // Convert to Finding
    let findings = plugin_output
        .findings
        .into_iter()
        .map(|pf| pf.into())
        .collect();

    Ok(findings)
}
