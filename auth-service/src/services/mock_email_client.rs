use color_eyre::eyre::Result;

use crate::domain::{Email, EmailClient};

pub struct MockEmailClient;

#[async_trait::async_trait]
impl EmailClient for MockEmailClient {
    async fn send_email(
        &self,
        _recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<()> {
        tracing::debug!(subject, content, "Sending email to [REDACTED]");
        Ok(())
    }
}
