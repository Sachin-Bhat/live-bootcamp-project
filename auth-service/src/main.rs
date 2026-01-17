use auth_service::Application;

#[tokio::main]
async fn main() {
    // Here we are using ip 0.0.0.0 so the service is listening on all the configured network interfaces.
    // This is needed for Docker to work, which we will add later on.
    // See: https://stackoverflow.com/questions/39525820/docker-port-forwarding-not-working
    let app = Application::build("0.0.0.0:3000")
        .await
        .expect("Failed to build application");

    app.run().await.expect("Failed to run application");
}
