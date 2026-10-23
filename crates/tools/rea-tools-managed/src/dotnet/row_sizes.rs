//! ECMA-335 metadata table row-size factories.
//!
//! Port of `src/dotnet/ManagedMetadataRowSizes.ts`.

use super::failure::{ManagedReaderFailure, managed_failure};

/// Row-size inputs: table index sizes, coded index sizes, and heap sizes.
pub struct RowSizeContext<'a> {
    pub table_size: &'a dyn Fn(usize) -> i64,
    pub coded_size: &'a dyn Fn(&str) -> i64,
    pub string_size: i64,
    pub guid_size: i64,
    pub blob_size: i64,
}

type RowSizeFactory = fn(&RowSizeContext<'_>) -> i64;

fn t(context: &RowSizeContext<'_>, index: usize) -> i64 {
    (context.table_size)(index)
}

fn c(context: &RowSizeContext<'_>, name: &str) -> i64 {
    (context.coded_size)(name)
}

const ROW_SIZE_FACTORIES: &[RowSizeFactory] = &[
    |x| 2 + x.string_size + x.guid_size * 3,
    |x| c(x, "ResolutionScope") + x.string_size * 2,
    |x| 4 + x.string_size * 2 + c(x, "TypeDefOrRef") + t(x, 3).max(t(x, 4)) + t(x, 5).max(t(x, 6)),
    |x| t(x, 4),
    |x| 2 + x.string_size + x.blob_size,
    |x| t(x, 6),
    |x| 8 + x.string_size + x.blob_size + t(x, 8),
    |x| t(x, 8),
    |x| 4 + x.string_size,
    |x| t(x, 2) + c(x, "TypeDefOrRef"),
    |x| c(x, "MemberRefParent") + x.string_size + x.blob_size,
    |x| 2 + c(x, "HasConstant") + x.blob_size,
    |x| c(x, "HasCustomAttribute") + c(x, "CustomAttributeType") + x.blob_size,
    |x| c(x, "HasFieldMarshal") + x.blob_size,
    |x| 2 + c(x, "HasDeclSecurity") + x.blob_size,
    |x| 6 + t(x, 2),
    |x| 4 + t(x, 4),
    |x| x.blob_size,
    |x| t(x, 2) + t(x, 20),
    |x| t(x, 20),
    |x| 2 + x.string_size + c(x, "TypeDefOrRef"),
    |x| t(x, 2) + t(x, 23),
    |x| t(x, 23),
    |x| 2 + x.string_size + x.blob_size,
    |x| 2 + t(x, 6) + c(x, "HasSemantics"),
    |x| t(x, 2) + c(x, "MethodDefOrRef") * 2,
    |x| x.string_size,
    |x| x.blob_size,
    |x| 2 + c(x, "MemberForwarded") + x.string_size + t(x, 26),
    |x| 4 + t(x, 4),
    |_| 8,
    |_| 4,
    |x| 16 + x.blob_size + x.string_size * 2,
    |_| 4,
    |_| 12,
    |x| 12 + x.blob_size * 2 + x.string_size * 2,
    |x| 4 + t(x, 35),
    |x| 12 + t(x, 35),
    |x| 4 + x.string_size + x.blob_size,
    |x| 8 + x.string_size * 2 + c(x, "Implementation"),
    |x| 8 + x.string_size + c(x, "Implementation"),
    |x| t(x, 2) * 2,
    |x| 4 + c(x, "TypeOrMethodDef") + x.string_size,
    |x| c(x, "MethodDefOrRef") + x.blob_size,
    |x| t(x, 42) + c(x, "TypeDefOrRef"),
];

/// `computeRowSize(table, context)`.
pub fn compute_row_size(
    table: usize,
    context: &RowSizeContext<'_>,
) -> Result<i64, ManagedReaderFailure> {
    match ROW_SIZE_FACTORIES.get(table) {
        Some(factory) => Ok(factory(context)),
        None => Err(managed_failure(
            "invalid-tables",
            "metadata.tables",
            format!("Metadata table {table} is unsupported"),
            None,
        )),
    }
}
