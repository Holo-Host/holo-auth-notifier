use ed25519_dalek::*;
use failure::*;
use hpos_config_core::{public_key, Config};
use lazy_static::*;
use reqwest::Client;
use serde::*;
use std::path::Path;
use std::time::Duration;
use std::{env, fs, fs::File, thread};
use tracing::*;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use uuid::Uuid;

fn get_holoport_url(id: PublicKey) -> String {
    if let Ok(network) = env::var("HOLO_NETWORK") {
        if network == "devNet" {
            return format!("https://{}.holohost.dev", public_key::to_base36_id(&id));
        }
    }
    format!("https://{}.holohost.net", public_key::to_base36_id(&id))
}

fn zt_auth_done_notification_path() -> String {
    match env::var("LED_NOTIFICATIONS_PATH") {
        Ok(path) => path,
        _ => "/var/lib/configure-holochain/zt-auth-done-notification".to_string(),
    }
}

fn device_bundle_password() -> Option<String> {
    match env::var("DEVICE_BUNDLE_PASSWORD") {
        Ok(pass) => Some(pass),
        _ => None,
    }
}

lazy_static! {
    static ref CLIENT: Client = Client::new();
}

fn get_hpos_config() -> Fallible<Config> {
    let config_path = env::var("HPOS_CONFIG_PATH")?;
    let config_json = fs::read(config_path)?;
    let config: Config = serde_json::from_slice(&config_json)?;
    Ok(config)
}

#[derive(Debug, Serialize)]
struct NotifyPayload {
    email: String,
    success: bool,
    data: String,
}

#[derive(Debug, Deserialize)]
struct PostmarkPromise {
    #[serde(rename = "MessageID")]
    message_id: Uuid,
}
async fn send_email(email: String, data: String, success: bool) -> Fallible<()> {
    let payload = NotifyPayload {
        email,
        success,
        data,
    };
    let url = format!("{}/v1/notify", env::var("AUTH_SERVER_URL")?);
    let resp = CLIENT.post(url).json(&payload).send().await?;
    info!("Response from email: {:?}", &resp);
    let promise: PostmarkPromise = resp.json().await?;
    info!("Postmark message ID: {}", promise.message_id);
    Ok(())
}

async fn retry_holoport_url(id: PublicKey) -> () {
    let url = get_holoport_url(id);
    let backoff = Duration::from_secs(5);
    loop {
        info!("Trying to connect to url: {}", url);
        if let Ok(resp) = CLIENT
            .get(url.clone())
            .timeout(std::time::Duration::from_millis(2000))
            .send()
            .await
        {
            match resp.error_for_status_ref() {
                Ok(_) => break,
                Err(e) => error!("{}", e),
            }
        }
        info!("Backing off for : {:?}", backoff);
        thread::sleep(backoff);
    }
}
async fn send_success_email(email: String, data: String) -> Fallible<()> {
    info!("Sending Confirmation Email to: {:?}", email);
    send_email(email, data, true).await
}

#[tokio::main]
async fn main() -> Fallible<()> {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    if Path::new(&zt_auth_done_notification_path()).exists() {
        let config = get_hpos_config()?;
        let password = device_bundle_password();
        let holochain_public_key =
            hpos_config_seed_bundle_explorer::holoport_public_key(&config, password).await?;

        // trying to connect to holoport admin portal
        retry_holoport_url(holochain_public_key).await;

        let email = match config {
            Config::V1 { settings, .. } | Config::V2 { settings, .. } => settings.admin.email,
        };
        // send successful email once we get a successful response from the holoport admin portal
        send_success_email(email.clone(), get_holoport_url(holochain_public_key)).await?;
        // Create a notification file that will be used by the LED notifier
        File::create(zt_auth_done_notification_path())?;
    }

    Ok(())
}
