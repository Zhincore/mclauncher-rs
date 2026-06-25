//! PortableMC is a library and CLI for programmatically launching Minecraft.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::double_must_use)]

mod http;
mod path;
mod serde;
mod tokio;

pub mod maven;

pub mod msa;

pub mod download;

pub mod base;
pub mod fabric;
pub mod forge;
pub mod moj;
