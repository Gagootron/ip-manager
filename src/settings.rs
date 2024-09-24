use std::net::IpAddr;
use std::str::FromStr;

use config::{Config, ConfigError, File};
use serde;
use serde::Deserialize;
use tiny_http::HeaderField;
use validator::Validate;
use std::{env, vec};

#[derive(Debug, Validate, Deserialize)]
#[allow(unused)]
pub struct Settings {
    pub listen_address: String,
    pub threads: usize,
    #[serde(rename(deserialize = "headers"))]
    read_headers: Vec<String>,
    #[serde(skip)]
    pub headers: Vec<HeaderField>,
    pub allow_list: Vec<IpAddr>,
    pub days: u32,
    #[validate(range(min = 0, max = 23))]
    pub hour: u8,
    #[validate(range(min = 0, max = 59))]
    pub minute: u8,
    pub prune_interval: u32,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let config_file = env::var("CONFIG").unwrap_or("config.toml".into());
        let s = Config::builder()
            .set_default("listen_address", "127.0.0.1:8080")?
            .set_default("threads", 1)?
            .set_default(
                "read_headers",
                vec![
                    "Remote-Email",
                    "Remote-Groups",
                    "Remote-Name",
                    "Remote-User",
                ],
            )?
            .set_default("allow_list", Vec::<String>::new())?
            .set_default("days", 0)?
            .set_default("hour", 3)?
            .set_default("minute", 0)?
            .set_default("prune_interval", 3600)?
            .add_source(File::with_name(&config_file))
            .build()?;

        match s.try_deserialize::<Self>() {
            Err(e) => Err(e),
            Ok(mut s) => {
                s.headers = s
                    .read_headers
                    .drain(0..)
                    .map(|x| HeaderField::from_str(&x).expect("Failed to parse header"))
                    .collect();
                Ok(s)
            }
        }
    }
}
