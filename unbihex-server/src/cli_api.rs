//! `unbihex api …`: calls the gRPC API of a running server, as `xray api` does.
//!
//! Flags are Go-style like Xray's (`-name v`, `-name=v`, `--name v`), and the output is
//! JSON shaped like Xray's: zero values are left out.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde_json::{Map, Value, json};
use tonic::transport::{Channel, Endpoint};

use crate::api::{add_user_operation, remove_user_operation, vless_account};
use crate::proto::xray::app::proxyman::command as hs;
use crate::proto::xray::app::stats::command as ss;
use hs::handler_service_client::HandlerServiceClient;
use ss::stats_service_client::StatsServiceClient;

const USAGE: &str = "usage: unbihex api <command> [-s 127.0.0.1:8080] [-t 3] ...
  stats -name <name> [-reset]          one counter, e.g. user>>>EMAIL>>>traffic>>>uplink
  statsquery [-pattern <text>] [-reset] counters whose name contains the text
  sysstats                             server uptime
  adu -tag <inbound> -id <uuid> -email <email> [-flow xtls-rprx-vision]
                                       add a VLESS user (Xray's adu reads config files instead)
  rmu -tag <inbound> <email>...        remove users
  inbounduser -tag <inbound> [-email <email>]
  inboundusercount -tag <inbound>
-s / --server is the API address (default 127.0.0.1:8080), -t / --timeout in seconds (default 3).";

/// Parsed command-line flags.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Flags {
    values: HashMap<String, String>,
    bools: HashSet<String>,
    /// Arguments that are not flags, in order.
    pub positional: Vec<String>,
}

impl Flags {
    /// Parses `args`: `values` take an argument, `bools` do not (`-reset`, `-reset=false`).
    /// `-s` and `-t` are short for `server` and `timeout`.
    pub fn parse(args: &[String], values: &[&str], bools: &[&str]) -> Result<Flags, String> {
        let mut f = Flags::default();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let Some(body) = a
                .strip_prefix("--")
                .or_else(|| a.strip_prefix('-'))
                .filter(|b| !b.is_empty())
            else {
                f.positional.push(a.clone());
                continue;
            };
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (body, None),
            };
            let name = match name {
                "s" => "server",
                "t" => "timeout",
                n => n,
            };
            if bools.contains(&name) {
                match inline.as_deref() {
                    None | Some("true") => f.bools.insert(name.to_string()),
                    Some("false") => f.bools.remove(name),
                    Some(v) => return Err(format!("-{name}: not a boolean: {v:?}")),
                };
            } else if values.contains(&name) || name == "server" || name == "timeout" {
                let v = match inline {
                    Some(v) => v,
                    None => it
                        .next()
                        .cloned()
                        .ok_or_else(|| format!("-{name} needs a value"))?,
                };
                f.values.insert(name.to_string(), v);
            } else {
                return Err(format!("unknown flag -{name}"));
            }
        }
        Ok(f)
    }

    /// A flag's value, if given.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// Whether a boolean flag is set.
    pub fn is_set(&self, name: &str) -> bool {
        self.bools.contains(name)
    }

    fn required(&self, name: &str) -> Result<&str, String> {
        self.get(name)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("-{name} is required"))
    }
}

/// Runs `unbihex api <args>`.
pub fn run(args: &[String]) -> Result<(), String> {
    let Some(cmd) = args.first().map(String::as_str) else {
        println!("{USAGE}");
        return Ok(());
    };
    let rest = args.get(1..).unwrap_or_default();
    let (values, bools): (&[&str], &[&str]) = match cmd {
        "help" | "-h" | "--help" => {
            println!("{USAGE}");
            return Ok(());
        }
        "stats" => (&["name"], &["reset"]),
        "statsquery" => (&["pattern"], &["reset"]),
        "sysstats" => (&[], &[]),
        "adu" => (&["tag", "id", "email", "flow"], &[]),
        "rmu" | "inboundusercount" => (&["tag"], &[]),
        "inbounduser" => (&["tag", "email"], &[]),
        other => return Err(format!("unknown api command {other:?}\n{USAGE}")),
    };
    let flags = Flags::parse(rest, values, bools)?;
    let server = flags.get("server").unwrap_or("127.0.0.1:8080").to_string();
    let timeout = match flags.get("timeout") {
        Some(t) => t
            .parse::<u64>()
            .map_err(|_| format!("-timeout: not a number of seconds: {t:?}"))?,
        None => 3,
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let out = rt.block_on(async {
        let channel = connect(&server, Duration::from_secs(timeout.max(1))).await?;
        call(cmd, &flags, channel)
            .await
            .map_err(|s| format!("{cmd}: {}", s.message()))
    })?;
    if let Some(v) = out {
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
        );
    }
    Ok(())
}

async fn connect(server: &str, timeout: Duration) -> Result<Channel, String> {
    Endpoint::from_shared(format!("http://{server}"))
        .map_err(|e| format!("-server {server:?}: {e}"))?
        .connect_timeout(timeout)
        .timeout(timeout)
        .connect()
        .await
        .map_err(|e| format!("cannot reach the API at {server}: {e}"))
}

/// Makes one call; the JSON to print, if the command prints anything.
async fn call(cmd: &str, f: &Flags, ch: Channel) -> Result<Option<Value>, tonic::Status> {
    let reset = f.is_set("reset");
    let bad = |e: String| tonic::Status::invalid_argument(e);
    Ok(Some(match cmd {
        "stats" => {
            let name = f.required("name").map_err(bad)?.to_string();
            let r = StatsServiceClient::new(ch)
                .get_stats(ss::GetStatsRequest { name, reset })
                .await?
                .into_inner();
            json!({ "stat": r.stat.map(stat_json) })
        }
        "statsquery" => {
            let pattern = f.get("pattern").unwrap_or_default().to_string();
            let r = StatsServiceClient::new(ch)
                .query_stats(ss::QueryStatsRequest { pattern, reset })
                .await?
                .into_inner();
            let stat: Vec<_> = r.stat.into_iter().map(stat_json).collect();
            json!({ "stat": stat })
        }
        "sysstats" => {
            let r = StatsServiceClient::new(ch)
                .get_sys_stats(ss::SysStatsRequest {})
                .await?
                .into_inner();
            sparse([("Uptime", u64::from(r.uptime))])
        }
        "adu" => {
            let op = add_user_operation(
                f.required("email").map_err(bad)?,
                f.required("id").map_err(bad)?,
                f.get("flow").unwrap_or_default(),
            );
            let tag = f.required("tag").map_err(bad)?.to_string();
            HandlerServiceClient::new(ch)
                .alter_inbound(hs::AlterInboundRequest {
                    tag,
                    operation: Some(op),
                })
                .await?;
            return Ok(None);
        }
        "rmu" => {
            let tag = f.required("tag").map_err(bad)?;
            if f.positional.is_empty() {
                return Err(bad("no emails to remove".into()));
            }
            let mut client = HandlerServiceClient::new(ch);
            for email in &f.positional {
                client
                    .alter_inbound(hs::AlterInboundRequest {
                        tag: tag.to_string(),
                        operation: Some(remove_user_operation(email)),
                    })
                    .await?;
            }
            return Ok(None);
        }
        "inbounduser" => {
            let r = HandlerServiceClient::new(ch)
                .get_inbound_users(hs::GetInboundUserRequest {
                    tag: f.required("tag").map_err(bad)?.to_string(),
                    email: f.get("email").unwrap_or_default().to_string(),
                })
                .await?
                .into_inner();
            let users: Vec<_> = r
                .users
                .iter()
                .map(|u| {
                    let mut m = Map::new();
                    if !u.email.is_empty() {
                        m.insert("email".into(), u.email.clone().into());
                    }
                    if let Some(a) = vless_account(u) {
                        let mut acc = Map::new();
                        acc.insert("@type".into(), crate::api::VLESS_ACCOUNT.into());
                        for (k, v) in [("id", a.id), ("flow", a.flow), ("encryption", a.encryption)]
                        {
                            if !v.is_empty() {
                                acc.insert(k.into(), v.into());
                            }
                        }
                        m.insert("account".into(), acc.into());
                    }
                    Value::Object(m)
                })
                .collect();
            json!({ "users": users })
        }
        "inboundusercount" => {
            let r = HandlerServiceClient::new(ch)
                .get_inbound_users_count(hs::GetInboundUserRequest {
                    tag: f.required("tag").map_err(bad)?.to_string(),
                    email: String::new(),
                })
                .await?
                .into_inner();
            sparse([("count", u64::try_from(r.count).unwrap_or_default())])
        }
        _ => return Err(bad(format!("unknown api command {cmd:?}"))),
    }))
}

fn stat_json(s: ss::Stat) -> Value {
    let mut m = Map::new();
    m.insert("name".into(), s.name.into());
    if s.value != 0 {
        m.insert("value".into(), s.value.into());
    }
    Value::Object(m)
}

/// An object of the non-zero fields.
fn sparse<const N: usize>(fields: [(&str, u64); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .filter(|(_, v)| *v != 0)
            .map(|(k, v)| (k.to_string(), v.into()))
            .collect(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn go_style_flags() {
        let f = Flags::parse(
            &args("-s 1.2.3.4:5 --name=a>>>b -reset --t 9"),
            &["name"],
            &["reset"],
        )
        .unwrap();
        assert_eq!(f.get("server"), Some("1.2.3.4:5"));
        assert_eq!(f.get("name"), Some("a>>>b"));
        assert_eq!(f.get("timeout"), Some("9"));
        assert!(f.is_set("reset"));

        let f = Flags::parse(&args("-reset=false --pattern x"), &["pattern"], &["reset"]).unwrap();
        assert!(!f.is_set("reset"));
        assert_eq!(f.get("pattern"), Some("x"));
    }

    #[test]
    fn positionals_and_mistakes() {
        let f = Flags::parse(&args("-tag in a@x b@x"), &["tag"], &[]).unwrap();
        assert_eq!(f.get("tag"), Some("in"));
        assert_eq!(f.positional, ["a@x", "b@x"]);
        assert!(Flags::parse(&args("-tag"), &["tag"], &[]).is_err());
        assert!(Flags::parse(&args("-what 1"), &["tag"], &[]).is_err());
        assert!(Flags::parse(&args("-reset=maybe"), &[], &["reset"]).is_err());
        assert!(f.required("email").is_err());
    }

    #[test]
    fn zero_values_are_left_out() {
        assert_eq!(sparse([("Uptime", 0)]), json!({}));
        assert_eq!(
            stat_json(ss::Stat {
                name: "n".into(),
                value: 0
            }),
            json!({"name": "n"})
        );
    }
}
