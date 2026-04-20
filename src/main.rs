#[tokio::main]
async fn main() {
    mipsorcu::server::runtime::run().await;
}
