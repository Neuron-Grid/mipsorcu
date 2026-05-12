#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

#[tokio::main]
async fn main() {
    mipsorcu::server::runtime::run_entrypoint().await;
}
