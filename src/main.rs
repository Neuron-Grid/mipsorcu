mod server;

#[tokio::main]
async fn main() {
    server::runtime::run().await;
}
