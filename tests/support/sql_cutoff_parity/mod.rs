//! Shared candidate-aware SQL cutoff parity support.

pub mod definitions;
pub mod fixture;
pub mod guards;
pub mod markers;
pub mod migrations;
pub mod pg_prove_local_socket_v1;
pub mod resolver;
mod trigger_sql_lexer;
pub mod trigger_vocabulary;
