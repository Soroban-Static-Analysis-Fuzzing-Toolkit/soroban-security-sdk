//! Compiled WebAssembly module analysis.
//!
//! Contract source is the right place to reason about authorization and storage
//! layout, but only the compiled module knows how much code an entrypoint really
//! runs and how much memory it asks for. This module parses a `.wasm` file into
//! the facts the budget estimator needs: exports, imports, memories, and a
//! per-function instruction profile including how much of it sits inside loops.
//!
//! Wasm-level findings are reported as `contractspecv0`-free structural facts on
//! purpose: no XDR decoding is attempted, so the analyser works with any SDK
//! version.

use std::collections::BTreeSet;

use wasmparser::{CompositeInnerType, Imports, Operator, Parser, Payload, TypeRef};

use crate::error::{Error, Result};
use crate::span::SourceSpan;

/// Kind of an exported item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    /// Exported function.
    Function,
    /// Exported memory.
    Memory,
    /// Exported table.
    Table,
    /// Exported global.
    Global,
}

/// A wasm export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmExport {
    /// Export name.
    pub name: String,
    /// What was exported.
    pub kind: ExportKind,
    /// Index in its index space.
    pub index: u32,
}

/// A wasm import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmImport {
    /// Import module, `env` for Soroban host functions.
    pub module: String,
    /// Import name, e.g. `require_auth`.
    pub name: String,
    /// Whether it is a function import.
    pub is_function: bool,
}

/// A defined memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmMemory {
    /// Initial size in 64 KiB pages.
    pub initial_pages: u64,
    /// Optional maximum size in pages.
    pub maximum_pages: Option<u64>,
    /// Whether the memory is shared.
    pub shared: bool,
}

/// A function signature, reduced to what the estimator needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmFuncType {
    /// Number of parameters.
    pub params: u32,
    /// Number of results.
    pub results: u32,
}

/// Instruction profile of one defined function.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WasmFunction {
    /// Global function index (after imported functions).
    pub index: u32,
    /// Index of its type.
    pub type_index: Option<u32>,
    /// Number of instructions in the body.
    pub instruction_count: u64,
    /// Number of instructions lexically inside a loop body.
    pub loop_instructions: u64,
    /// Number of loops in the body.
    pub loop_count: u32,
    /// Deepest loop nesting.
    pub max_loop_depth: u32,
    /// Direct callee indices.
    pub calls: Vec<u32>,
    /// Whether the function makes an indirect call.
    pub has_call_indirect: bool,
    /// Whether the function grows memory.
    pub has_memory_grow: bool,
    /// Whether the function uses bulk-memory operations with dynamic sizes.
    pub has_bulk_memory: bool,
    /// Declared locals.
    pub local_count: u32,
}

impl WasmFunction {
    /// Instructions outside of any loop body.
    pub fn straight_line_instructions(&self) -> u64 {
        self.instruction_count.saturating_sub(self.loop_instructions)
    }

    /// Whether the function contains control flow that hides its real cost.
    pub fn is_hard_to_bound(&self) -> bool {
        self.loop_instructions > 0
            || self.has_call_indirect
            || self.has_memory_grow
            || self.has_bulk_memory
    }
}

/// A custom section, as `(name, size in bytes)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmCustomSection {
    /// Section name.
    pub name: String,
    /// Size of the section payload.
    pub size: usize,
}

/// A parsed wasm module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmModule {
    /// Display path of the module.
    pub name: String,
    /// Size of the module in bytes.
    pub size_bytes: usize,
    /// Exports.
    pub exports: Vec<WasmExport>,
    /// Imports.
    pub imports: Vec<WasmImport>,
    /// Defined memories.
    pub memories: Vec<WasmMemory>,
    /// Function types.
    pub types: Vec<WasmFuncType>,
    /// Defined functions, in index order.
    pub functions: Vec<WasmFunction>,
    /// Custom sections.
    pub custom_sections: Vec<WasmCustomSection>,
    /// Whether the module declares a start function.
    pub has_start: bool,
    /// Number of imported functions; defined functions start at this index.
    pub imported_function_count: u32,
    /// Number of globals.
    pub global_count: u32,
    /// Number of tables.
    pub table_count: u32,
    /// Number of data segments.
    pub data_segment_count: u32,
    /// Number of element segments.
    pub element_segment_count: u32,
}

impl WasmModule {
    /// Parse a wasm module from bytes.
    pub fn parse(name: impl Into<String>, bytes: &[u8]) -> Result<Self> {
        let name = name.into();
        let mut module = WasmModule {
            name: name.clone(),
            size_bytes: bytes.len(),
            exports: Vec::new(),
            imports: Vec::new(),
            memories: Vec::new(),
            types: Vec::new(),
            functions: Vec::new(),
            custom_sections: Vec::new(),
            has_start: false,
            imported_function_count: 0,
            global_count: 0,
            table_count: 0,
            data_segment_count: 0,
            element_segment_count: 0,
        };
        let mut function_type_indices: Vec<u32> = Vec::new();

        for payload in Parser::new(0).parse_all(bytes) {
            let payload = payload.map_err(|err| Error::Wasm {
                path: name.clone().into(),
                message: err.to_string(),
            })?;
            match payload {
                Payload::TypeSection(reader) => {
                    for group in reader {
                        let group = group.map_err(|err| wasm_error(&name, err))?;
                        for subtype in group.types() {
                            if let CompositeInnerType::Func(func) = &subtype.composite_type.inner {
                                module.types.push(WasmFuncType {
                                    params: func.params().len() as u32,
                                    results: func.results().len() as u32,
                                });
                            } else {
                                module.types.push(WasmFuncType {
                                    params: 0,
                                    results: 0,
                                });
                            }
                        }
                    }
                }
                Payload::ImportSection(reader) => {
                    for group in reader {
                        match group.map_err(|err| wasm_error(&name, err))? {
                            Imports::Single(_, import) => push_import(&mut module, import),
                            Imports::Compact1 { module: import_module, items } => {
                                for item in items {
                                    let item = item.map_err(|err| wasm_error(&name, err))?;
                                    push_import_parts(
                                        &mut module,
                                        import_module,
                                        item.name,
                                        item.ty,
                                    );
                                }
                            }
                            Imports::Compact2 {
                                module: import_module,
                                ty,
                                names,
                            } => {
                                for item in names {
                                    let item = item.map_err(|err| wasm_error(&name, err))?;
                                    push_import_parts(&mut module, import_module, item, ty);
                                }
                            }
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for index in reader {
                        function_type_indices
                            .push(index.map_err(|err| wasm_error(&name, err))?);
                    }
                }
                Payload::MemorySection(reader) => {
                    for memory in reader {
                        let memory = memory.map_err(|err| wasm_error(&name, err))?;
                        module.memories.push(WasmMemory {
                            initial_pages: memory.initial,
                            maximum_pages: memory.maximum,
                            shared: memory.shared,
                        });
                    }
                }
                Payload::GlobalSection(reader) => {
                    module.global_count = reader.count();
                }
                Payload::TableSection(reader) => {
                    module.table_count = reader.count();
                }
                Payload::DataSection(reader) => {
                    module.data_segment_count = reader.count();
                }
                Payload::ElementSection(reader) => {
                    module.element_segment_count = reader.count();
                }
                Payload::StartSection { .. } => {
                    module.has_start = true;
                }
                Payload::ExportSection(reader) => {
                    for export in reader {
                        let export = export.map_err(|err| wasm_error(&name, err))?;
                        module.exports.push(WasmExport {
                            name: export.name.to_string(),
                            kind: match export.kind {
                                wasmparser::ExternalKind::Func => ExportKind::Function,
                                wasmparser::ExternalKind::Memory => ExportKind::Memory,
                                wasmparser::ExternalKind::Table => ExportKind::Table,
                                wasmparser::ExternalKind::Global => ExportKind::Global,
                                _ => ExportKind::Global,
                            },
                            index: export.index,
                        });
                    }
                }
                Payload::CustomSection(reader) => {
                    module.custom_sections.push(WasmCustomSection {
                        name: reader.name().to_string(),
                        size: reader.data().len(),
                    });
                }
                Payload::CodeSectionEntry(body) => {
                    let defined_index = module.functions.len() as u32;
                    let index = module.imported_function_count + defined_index;
                    let type_index = function_type_indices
                        .get(defined_index as usize)
                        .copied();
                    // Locals are encoded as `(count, type)` groups; the number of
                    // locals is the sum of the group counts.
                    let mut local_count = 0u32;
                    let locals = body
                        .get_locals_reader()
                        .map_err(|err| wasm_error(&name, err))?;
                    for group in locals {
                        let (count, _ty) = group.map_err(|err| wasm_error(&name, err))?;
                        local_count += count;
                    }
                    let profile = profile_body(&body, &name)?;
                    module.functions.push(WasmFunction {
                        index,
                        type_index,
                        local_count,
                        ..profile
                    });
                }
                _ => {}
            }
        }

        Ok(module)
    }

    /// Load and parse a wasm file.
    pub fn from_path(path: impl AsRef<std::path::Path>, display: impl Into<String>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(Error::io(path))?;
        WasmModule::parse(display, &bytes)
    }

    /// Exported functions with their profiles.
    pub fn exported_functions(&self) -> impl Iterator<Item = (&WasmExport, &WasmFunction)> {
        self.exports
            .iter()
            .filter(|export| export.kind == ExportKind::Function)
            .filter_map(move |export| {
                self.function(export.index).map(|function| (export, function))
            })
    }

    /// Look up a function by its global index.
    pub fn function(&self, index: u32) -> Option<&WasmFunction> {
        index
            .checked_sub(self.imported_function_count)
            .and_then(|defined| self.functions.get(defined as usize))
    }

    /// Names of exported functions.
    pub fn exported_function_names(&self) -> Vec<&str> {
        self.exports
            .iter()
            .filter(|export| export.kind == ExportKind::Function)
            .map(|export| export.name.as_str())
            .collect()
    }

    /// Names of imported functions, deduplicated and sorted.
    pub fn import_names(&self) -> BTreeSet<&str> {
        self.imports
            .iter()
            .filter(|import| import.is_function)
            .map(|import| import.name.as_str())
            .collect()
    }

    /// Whether a host import is used.
    pub fn imports(&self, name: &str) -> bool {
        self.imports
            .iter()
            .any(|import| import.name == name && import.is_function)
    }

    /// Memory the module requests at instantiation, in bytes.
    pub fn memory_bytes(&self) -> u64 {
        self.memories
            .iter()
            .map(|memory| memory.initial_pages * 65_536)
            .max()
            .unwrap_or(0)
    }

    /// Total instructions across all defined functions.
    pub fn total_instructions(&self) -> u64 {
        self.functions
            .iter()
            .map(|function| function.instruction_count)
            .sum()
    }

    /// Whether the module carries the Soroban contract spec section.
    pub fn has_contract_spec(&self) -> bool {
        self.custom_sections
            .iter()
            .any(|section| section.name == "contractspecv0")
    }

    /// Confidence-less description of the module, used in reports.
    pub fn describe(&self) -> String {
        format!(
            "{} ({} KiB, {} exported functions, {} imports, {} KiB memory)",
            self.name,
            self.size_bytes / 1024,
            self.exported_function_names().len(),
            self.imports.len(),
            self.memory_bytes() / 1024
        )
    }
}

fn push_import(module: &mut WasmModule, import: wasmparser::Import<'_>) {
    push_import_parts(module, import.module, import.name, import.ty);
}

fn push_import_parts(module: &mut WasmModule, import_module: &str, name: &str, ty: TypeRef) {
    let is_function = matches!(ty, TypeRef::Func(_));
    if is_function {
        module.imported_function_count += 1;
    }
    module.imports.push(WasmImport {
        module: import_module.to_string(),
        name: name.to_string(),
        is_function,
    });
}

fn wasm_error(name: &str, err: wasmparser::BinaryReaderError) -> Error {
    Error::Wasm {
        path: name.into(),
        message: err.to_string(),
    }
}

/// Count instructions and record control-flow facts for one function body.
fn profile_body(body: &wasmparser::FunctionBody<'_>, name: &str) -> Result<WasmFunction> {
    let mut profile = WasmFunction::default();
    let mut reader = body
        .get_operators_reader()
        .map_err(|err| wasm_error(name, err))?;
    // `true` marks the frame of a loop, which is the only block that can repeat.
    let mut blocks: Vec<bool> = Vec::new();
    while !reader.eof() {
        let operator = reader.read().map_err(|err| wasm_error(name, err))?;
        profile.instruction_count += 1;
        let inside_loop = blocks.contains(&true);
        if inside_loop {
            profile.loop_instructions += 1;
        }
        match operator {
            Operator::Loop { .. } => {
                blocks.push(true);
                profile.loop_count += 1;
                profile.max_loop_depth =
                    profile.max_loop_depth.max(blocks.iter().filter(|is_loop| **is_loop).count() as u32);
            }
            Operator::Block { .. } | Operator::If { .. } | Operator::Try { .. } => blocks.push(false),
            Operator::End => {
                blocks.pop();
            }
            Operator::Call { function_index } => profile.calls.push(function_index),
            Operator::CallIndirect { .. } | Operator::ReturnCallIndirect { .. } => {
                profile.has_call_indirect = true
            }
            Operator::MemoryGrow { .. } => profile.has_memory_grow = true,
            Operator::MemoryCopy { .. }
            | Operator::MemoryFill { .. }
            | Operator::MemoryInit { .. }
            | Operator::TableCopy { .. }
            | Operator::TableFill { .. }
            | Operator::TableInit { .. } => profile.has_bulk_memory = true,
            _ => {}
        }
    }
    Ok(profile)
}

/// Span placeholder for wasm-level findings, which have byte offsets instead of
/// source positions.
pub const NO_SPAN: SourceSpan = SourceSpan::UNKNOWN;

#[cfg(test)]
mod tests {
    use super::*;

    fn wat(source: &str) -> Vec<u8> {
        wat::parse_str(source).unwrap()
    }

    #[test]
    fn parses_exports_imports_and_memory() {
        let bytes = wat(
            r#"
(module
  (import "env" "require_auth" (func $require_auth (param i64)))
  (import "env" "storage_get" (func $storage_get (param i64) (result i64)))
  (memory 2 4)
  (func $transfer (param i64) (result i64)
    (call $require_auth (local.get 0))
    (call $storage_get (local.get 0)))
  (export "transfer" (func $transfer))
)
"#,
        );
        let module = WasmModule::parse("target/wasm32/contract.wasm", &bytes).unwrap();
        assert_eq!(module.exported_function_names(), vec!["transfer"]);
        assert_eq!(module.imported_function_count, 2);
        assert!(module.imports("require_auth"));
        assert_eq!(module.memory_bytes(), 2 * 65_536);
        assert_eq!(module.memories[0].maximum_pages, Some(4));
        assert!(!module.has_contract_spec());
        let (export, function) = module.exported_functions().next().unwrap();
        assert_eq!(export.index, 2, "defined functions start after the imports");
        assert_eq!(function.index, 2);
        assert_eq!(function.calls.len(), 2);
        assert_eq!(function.local_count, 0);
        assert!(function.instruction_count > 0);
        assert!(!function.is_hard_to_bound());
    }

    #[test]
    fn counts_instructions_inside_loops() {
        let bytes = wat(
            r#"
(module
  (func $iterate (param i32)
    (local i32)
    (loop $outer
      (local.set 1 (i32.const 0))
      (block $inner
        (loop $nested
          (br_if $nested (i32.const 0))
        )
      )
      (br_if $outer (i32.const 0))
    )
    (i32.const 1)
    drop)
  (export "iterate" (func $iterate))
)
"#,
        );
        let module = WasmModule::parse("m.wasm", &bytes).unwrap();
        let function = &module.functions[0];
        assert_eq!(function.loop_count, 2);
        assert_eq!(function.max_loop_depth, 2);
        assert!(function.loop_instructions > 0);
        assert!(function.straight_line_instructions() > 0);
        assert!(function.is_hard_to_bound());
        assert_eq!(
            function.instruction_count,
            function.straight_line_instructions() + function.loop_instructions
        );
    }

    #[test]
    fn detects_indirect_calls_and_memory_growth() {
        let bytes = wat(
            r#"
(module
  (type $sig (func))
  (table 1 funcref)
  (memory 1)
  (func $f
    (call_indirect (type $sig) (i32.const 0))
    (memory.grow (i32.const 1))
    drop)
  (export "f" (func $f))
)
"#,
        );
        let module = WasmModule::parse("m.wasm", &bytes).unwrap();
        let function = &module.functions[0];
        assert!(function.has_call_indirect);
        assert!(function.has_memory_grow);
        assert!(function.is_hard_to_bound());
    }

    #[test]
    fn reports_custom_sections_and_start() {
        let bytes = wat(
            r#"
(module
  (memory 1)
  (@custom "contractspecv0" "abc")
  (func $start)
  (start $start)
  (export "start" (func $start))
)
"#,
        );
        let module = WasmModule::parse("m.wasm", &bytes).unwrap();
        assert!(module.has_contract_spec());
        assert!(module.has_start);
        assert!(module.custom_sections.iter().any(|s| s.name == "contractspecv0"));
    }

    #[test]
    fn rejects_invalid_modules() {
        let error = WasmModule::parse("m.wasm", b"not wasm at all").unwrap_err();
        assert!(matches!(error, Error::Wasm { .. }));
        assert!(error.to_string().contains("m.wasm"));
    }

    #[test]
    fn describe_summarises_the_module() {
        let bytes = wat("(module (memory 1) (func $f) (export \"f\" (func $f)))");
        let module = WasmModule::parse("m.wasm", &bytes).unwrap();
        let description = module.describe();
        assert!(description.contains("1 exported functions"));
        assert!(description.contains("64 KiB memory"));
        assert_eq!(module.total_instructions(), module.functions[0].instruction_count);
    }
}
