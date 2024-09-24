mod settings;
use chrono::prelude::*;
use chrono::Days;
use chrono::TimeDelta;
use ctrlc;
use log::{debug, error, info, trace, warn};
use settings::Settings;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread;
use std::time::Duration;
use tiny_http::{Header, HeaderField, Request, Response, Server};
use validator::Validate;

#[derive(Clone)]
struct WhitelistElement {
    valid_until: DateTime<Utc>,
    headers: Vec<Header>,
}

struct IpWhitelist {
    list: RwLock<HashMap<IpAddr, WhitelistElement>>,
    minute: u8,
    hour: u8,
    days: u32,
}

impl IpWhitelist {
    fn build(minute: u8, hour: u8, days: u32) -> Self {
        Self {
            list: RwLock::new(HashMap::new()),
            minute,
            hour,
            days,
        }
    }

    fn is_allowed(&self, addr: &IpAddr) -> Result<Vec<Header>, ()> {
        if let Some(x) = self.get_ip(addr) {
            trace!("{:#}",x.valid_until.signed_duration_since(Utc::now()));
            if x.valid_until.signed_duration_since(Utc::now()) > TimeDelta::zero() {
                Ok(x.headers.clone())
            } else {
                debug!("Expired IP: {addr}");
                self.delete_ip(addr);
                Err(())
            }
        } else {
            Err(())
        }
    }

    fn get_ip(&self, addr: &IpAddr) -> Option<WhitelistElement> {
        if let Some(x) = self.list.read().expect("Whitelist is poisoned").get(addr) {
            Some(x.clone())
        } else {
            None
        }
    }

    fn delete_ip(&self, addr: &IpAddr) {
        self.list
            .write()
            .expect("Whitelist is poisoned")
            .remove(addr);
    }

    fn allow(&self, addr: &IpAddr, headers: &[Header]) {
        let mut list = self.list.write().expect("Whitelist is poisoned");
        list.insert(
            *addr,
            WhitelistElement {
                valid_until: self.new_valid_until(),
                headers: headers.to_vec(),
            },
        );
    }

    fn new_valid_until(&self) -> DateTime<Utc> {
        let time = NaiveTime::from_hms_opt(self.hour.into(), self.minute.into(), 0).unwrap();
        let mut date: DateTime<Utc> = Utc::now();
        trace!("{:#}",date);
        date = date.checked_add_days(Days::new(self.days.into())).unwrap();
        if (date - date.with_time(time).unwrap()) > TimeDelta::zero() {
            date = date
                .checked_add_days(Days::new(1))
                .unwrap()
                .with_time(time)
                .unwrap();
        } else {
            date = date.with_time(time).unwrap()
        }
        trace!("{:#}",date);
        return date;
    }

    fn prune(&self) {
        let mut list = self.list.write().expect("Whitelist is poisoned");
        let now = Utc::now();
        let zero = TimeDelta::zero();
        list.retain(|_, v| v.valid_until.signed_duration_since(now) > zero);
    }
}

fn main() -> ExitCode {
    env_logger::init();
    let settings = Settings::new();
    if let Err(error) = settings {
        error!("Failed to parse config: {}", error);
        return ExitCode::FAILURE;
    }
    let settings = settings.unwrap();
    if let Err(error) = settings.validate() {
        error!("Failed to validate config: {}", error);
        return ExitCode::FAILURE;
    }
    let settings = Arc::new(settings);
    let server = Arc::new(Server::http(&settings.listen_address).unwrap());
    let mut guards = Vec::with_capacity(settings.threads);
    let whitelist = Arc::new(IpWhitelist::build(
        settings.minute,
        settings.hour,
        settings.days,
    ));

    {
        let settings = settings.clone();
        let server = server.clone();
        ctrlc::set_handler(move || {
            info!("Caught Ctrl-C");
            for _ in 0..settings.threads {
                server.unblock();
            }
        })
        .expect("Error setting Ctrl-C handler");
    }

    for _ in 0..settings.threads {
        let settings = settings.clone();
        let server = server.clone();
        let whitelist = whitelist.clone();
        let guard = thread::spawn(move || {
            server_thread(server, &settings, whitelist);
        });

        guards.push(guard);
    }

    let _pruner = {
        let whitelist = whitelist.clone();
        let settings = settings.clone();
        thread::spawn(move || loop {
            whitelist.prune();
            trace!("Pruner run");
            thread::sleep(Duration::from_secs(settings.prune_interval.into()));
        })
    };

    for guard in guards {
        let _ = guard.join();
    }
    info!("Server exit");
    ExitCode::SUCCESS
}

fn server_thread(server: Arc<Server>, settings: &Settings, whitelist: Arc<IpWhitelist>) {
    loop {
        if let Ok(rq) = server.recv() {
            trace!(
                "received request. method: {:?}, url: {:?}, headers: {:?}",
                rq.method(),
                rq.url(),
                rq.headers()
            );
            match rq.url() {
                "/allowed" => allowed(settings, &whitelist, rq),
                "/authorize" => authorize(settings, &whitelist, rq),
                _ => rq
                    .respond(Response::from_string("not found").with_status_code(404))
                    .unwrap(),
            }
        } else {
            debug!("Thread exit");
            break;
        }
    }
}

fn get_ip(rq: &Request) -> IpAddr {
    for header in rq.headers() {
        if header.field == HeaderField::from_str("X-Forwarded-For").unwrap() {
            if let Ok(ip) = IpAddr::from_str(header.value.as_str()) {
                return ip;
            } else {
                warn!("Got request with invalid IP Header: \"{header}\"");
            }
        }
    }
    rq.remote_addr().unwrap().ip()
}

fn allowed(settings: &Settings, whitelist: &IpWhitelist, rq: Request) {
    let addr = get_ip(&rq);

    if settings.allow_list.contains(&addr){
        let _ = rq.respond(Response::from_string("Ok"));
        return;
    }

    if let Ok(headers) = whitelist.is_allowed(&addr) {
        debug!("Allowed request from {addr}");
        let mut response = Response::from_string("Ok");
        for header in headers {
            response.add_header(header);
        }
        let _ = rq.respond(response);
    } else {
        debug!("Forbidden request from {addr}");
        let _ = rq.respond(
            Response::from_string("Please (re)authenticate yourself").with_status_code(403),
        );
    }
}

fn authorize(settings: &Settings, whitelist: &IpWhitelist, rq: Request){
    let addr = get_ip(&rq);
    let headers: Vec<_> = rq
        .headers()
        .iter()
        .filter(|x| settings.headers.contains(&x.field))
        .cloned()
        .collect();
    info!(
        "Authorized {addr} with headers: {}",
        headers
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join("; ")
    );

    whitelist.allow(&addr, &headers);
    let _ = rq.respond(Response::from_string("Ok"));
}
