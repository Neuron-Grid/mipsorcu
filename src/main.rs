#[tokio::main]
async fn main() {
    mipsorcu::server::runtime::run_entrypoint().await;
}
