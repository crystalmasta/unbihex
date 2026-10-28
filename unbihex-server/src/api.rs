//! The management API, compatible with Xray's: StatsService and HandlerService on the
//! same gRPC paths, so panels (Marzban, 3x-ui, PasarGuard) and `xray api` talk to us unchanged.
//!
//! Users are VLESS only. Adding and removing inbounds and outbounds is not supported:
//! those calls answer `Unimplemented`.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use prost::Message;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};
use unbihex_engine::config::{Secret, VlessUser};
use unbihex_engine::server::ServerControl;

use crate::proto::xray::app::proxyman::command as hs;
use crate::proto::xray::app::stats::command as ss;
use crate::proto::xray::common::protocol::User;
use crate::proto::xray::common::serial::TypedMessage;
use crate::proto::xray::proxy::vless::Account;
use hs::handler_service_server::{HandlerService, HandlerServiceServer};
use ss::stats_service_server::{StatsService, StatsServiceServer};

/// `TypedMessage.type` of the messages we read and write.
pub const ADD_USER: &str = "xray.app.proxyman.command.AddUserOperation";
/// See [`ADD_USER`].
pub const REMOVE_USER: &str = "xray.app.proxyman.command.RemoveUserOperation";
/// See [`ADD_USER`].
pub const VLESS_ACCOUNT: &str = "xray.proxy.vless.Account";

const STATS: &str = "StatsService";
const HANDLER: &str = "HandlerService";

/// The `api` section of the server config, as in Xray (`api.listen`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// Where the gRPC API listens, e.g. `127.0.0.1:10085`.
    pub listen: SocketAddr,
    /// Xray's tag of the API inbound; not needed when `listen` is given.
    #[serde(default)]
    pub tag: String,
    /// Services to serve: `StatsService`, `HandlerService`; empty means both.
    #[serde(default)]
    pub services: Vec<String>,
}

impl ApiConfig {
    fn serves(&self, service: &str) -> bool {
        self.services.is_empty() || self.services.iter().any(|s| s == service)
    }

    /// Rejects services we do not have, rather than leaving them silently out.
    pub fn validate(&self) -> Result<(), String> {
        match self.services.iter().find(|s| *s != STATS && *s != HANDLER) {
            Some(s) => Err(format!("api: service {s:?} is not supported")),
            None => Ok(()),
        }
    }
}

/// Serves the API on `listen` until `shutdown` completes.
pub async fn serve(
    cfg: &ApiConfig,
    control: Arc<ServerControl>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), String> {
    let listener = TcpListener::bind(cfg.listen)
        .await
        .map_err(|e| format!("api: cannot listen on {}: {e}", cfg.listen))?;
    serve_listener(cfg, listener, control, shutdown).await
}

/// Serves the API on a bound listener until `shutdown` completes.
pub async fn serve_listener(
    cfg: &ApiConfig,
    listener: TcpListener,
    control: Arc<ServerControl>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), String> {
    cfg.validate()?;
    if let Ok(addr) = listener.local_addr() {
        tracing::info!("api listening on {addr}");
    }
    let api = Api {
        control,
        started: Instant::now(),
    };
    let stats = cfg
        .serves(STATS)
        .then(|| StatsServiceServer::new(api.clone()));
    let handler = cfg.serves(HANDLER).then(|| HandlerServiceServer::new(api));
    tonic::transport::Server::builder()
        .add_optional_service(stats)
        .add_optional_service(handler)
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await
        .map_err(|e| format!("api: {e}"))
}

#[derive(Clone)]
struct Api {
    control: Arc<ServerControl>,
    started: Instant,
}

/// Engine errors reach the caller as Xray's do: code Unknown, the reason in the text.
fn unknown(e: impl std::fmt::Display) -> Status {
    Status::unknown(e.to_string())
}

#[tonic::async_trait]
impl StatsService for Api {
    async fn get_stats(
        &self,
        req: Request<ss::GetStatsRequest>,
    ) -> Result<Response<ss::GetStatsResponse>, Status> {
        let r = req.into_inner();
        let value = self
            .control
            .stats()
            .get(&r.name, r.reset)
            .ok_or_else(|| Status::unknown(format!("{} not found.", r.name)))?;
        Ok(Response::new(ss::GetStatsResponse {
            stat: Some(ss::Stat {
                name: r.name,
                value,
            }),
        }))
    }

    async fn get_stats_online(
        &self,
        _: Request<ss::GetStatsRequest>,
    ) -> Result<Response<ss::GetStatsResponse>, Status> {
        Err(Status::unimplemented("online stats are not supported"))
    }

    async fn query_stats(
        &self,
        req: Request<ss::QueryStatsRequest>,
    ) -> Result<Response<ss::QueryStatsResponse>, Status> {
        let r = req.into_inner();
        let stat = self
            .control
            .stats()
            .query(&r.pattern, r.reset)
            .into_iter()
            .map(|(name, value)| ss::Stat { name, value })
            .collect();
        Ok(Response::new(ss::QueryStatsResponse { stat }))
    }

    async fn get_sys_stats(
        &self,
        _: Request<ss::SysStatsRequest>,
    ) -> Result<Response<ss::SysStatsResponse>, Status> {
        let uptime = u32::try_from(self.started.elapsed().as_secs()).unwrap_or(u32::MAX);
        Ok(Response::new(ss::SysStatsResponse {
            uptime,
            ..Default::default()
        }))
    }

    async fn get_stats_online_ip_list(
        &self,
        _: Request<ss::GetStatsRequest>,
    ) -> Result<Response<ss::GetStatsOnlineIpListResponse>, Status> {
        Err(Status::unimplemented("online stats are not supported"))
    }

    async fn get_all_online_users(
        &self,
        _: Request<ss::GetAllOnlineUsersRequest>,
    ) -> Result<Response<ss::GetAllOnlineUsersResponse>, Status> {
        Err(Status::unimplemented("online stats are not supported"))
    }

    async fn get_users_stats(
        &self,
        req: Request<ss::GetUsersStatsRequest>,
    ) -> Result<Response<ss::GetUsersStatsResponse>, Status> {
        let r = req.into_inner();
        let users = self
            .control
            .stats()
            .users_traffic(r.reset)
            .into_iter()
            .map(|(email, uplink, downlink)| ss::UserStat {
                email,
                ips: Vec::new(),
                traffic: r
                    .include_traffic
                    .then_some(ss::TrafficUserStat { uplink, downlink }),
            })
            .collect();
        Ok(Response::new(ss::GetUsersStatsResponse { users }))
    }
}

/// The VLESS user an `AddUserOperation` carries.
fn vless_user(user: Option<User>) -> Result<VlessUser, Status> {
    let user = user.ok_or_else(|| Status::invalid_argument("no user"))?;
    let account = user
        .account
        .ok_or_else(|| Status::invalid_argument("user has no account"))?;
    if account.r#type != VLESS_ACCOUNT {
        return Err(Status::invalid_argument(format!(
            "account {:?}: only VLESS accounts are supported",
            account.r#type
        )));
    }
    let a = Account::decode(account.value.as_slice())
        .map_err(|e| Status::invalid_argument(format!("vless account: {e}")))?;
    if !(a.encryption.is_empty() || a.encryption == "none") {
        return Err(Status::invalid_argument(format!(
            "vless encryption {:?} is not supported",
            a.encryption
        )));
    }
    Ok(VlessUser {
        id: Secret(a.id),
        email: user.email,
        flow: a.flow,
    })
}

/// Our user as Xray describes it.
fn xray_user(u: VlessUser) -> User {
    let account = Account {
        id: u.id.expose().to_string(),
        flow: u.flow,
        encryption: "none".into(),
        ..Default::default()
    };
    User {
        level: 0,
        email: u.email,
        account: Some(TypedMessage {
            r#type: VLESS_ACCOUNT.into(),
            value: account.encode_to_vec(),
        }),
    }
}

fn unimplemented<T>(what: &str) -> Result<Response<T>, Status> {
    Err(Status::unimplemented(format!("{what} is not supported")))
}

#[tonic::async_trait]
impl HandlerService for Api {
    async fn add_inbound(
        &self,
        _: Request<hs::AddInboundRequest>,
    ) -> Result<Response<hs::AddInboundResponse>, Status> {
        unimplemented("AddInbound")
    }

    async fn remove_inbound(
        &self,
        _: Request<hs::RemoveInboundRequest>,
    ) -> Result<Response<hs::RemoveInboundResponse>, Status> {
        unimplemented("RemoveInbound")
    }

    async fn alter_inbound(
        &self,
        req: Request<hs::AlterInboundRequest>,
    ) -> Result<Response<hs::AlterInboundResponse>, Status> {
        let r = req.into_inner();
        let op = r
            .operation
            .ok_or_else(|| Status::invalid_argument("no operation"))?;
        let bad = |e: prost::DecodeError| Status::invalid_argument(format!("{}: {e}", op.r#type));
        match op.r#type.as_str() {
            ADD_USER => {
                let add = hs::AddUserOperation::decode(op.value.as_slice()).map_err(bad)?;
                let user = vless_user(add.user)?;
                self.control.add_user(&r.tag, user).map_err(unknown)?;
            }
            REMOVE_USER => {
                let rm = hs::RemoveUserOperation::decode(op.value.as_slice()).map_err(bad)?;
                self.control
                    .remove_user(&r.tag, &rm.email)
                    .map_err(unknown)?;
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "operation {other:?} is not supported"
                )));
            }
        }
        Ok(Response::new(hs::AlterInboundResponse {}))
    }

    async fn list_inbounds(
        &self,
        _: Request<hs::ListInboundsRequest>,
    ) -> Result<Response<hs::ListInboundsResponse>, Status> {
        unimplemented("ListInbounds")
    }

    async fn get_inbound_users(
        &self,
        req: Request<hs::GetInboundUserRequest>,
    ) -> Result<Response<hs::GetInboundUserResponse>, Status> {
        let r = req.into_inner();
        let users = self
            .control
            .users(&r.tag, Some(&r.email))
            .map_err(unknown)?
            .into_iter()
            .map(xray_user)
            .collect();
        Ok(Response::new(hs::GetInboundUserResponse { users }))
    }

    async fn get_inbound_users_count(
        &self,
        req: Request<hs::GetInboundUserRequest>,
    ) -> Result<Response<hs::GetInboundUsersCountResponse>, Status> {
        let n = self
            .control
            .user_count(&req.into_inner().tag)
            .map_err(unknown)?;
        Ok(Response::new(hs::GetInboundUsersCountResponse {
            count: i64::try_from(n).unwrap_or(i64::MAX),
        }))
    }

    async fn add_outbound(
        &self,
        _: Request<hs::AddOutboundRequest>,
    ) -> Result<Response<hs::AddOutboundResponse>, Status> {
        unimplemented("AddOutbound")
    }

    async fn remove_outbound(
        &self,
        _: Request<hs::RemoveOutboundRequest>,
    ) -> Result<Response<hs::RemoveOutboundResponse>, Status> {
        unimplemented("RemoveOutbound")
    }

    async fn alter_outbound(
        &self,
        _: Request<hs::AlterOutboundRequest>,
    ) -> Result<Response<hs::AlterOutboundResponse>, Status> {
        unimplemented("AlterOutbound")
    }

    async fn list_outbounds(
        &self,
        _: Request<hs::ListOutboundsRequest>,
    ) -> Result<Response<hs::ListOutboundsResponse>, Status> {
        unimplemented("ListOutbounds")
    }
}

/// An `AlterInbound` operation that adds a VLESS user (for clients of this API).
pub fn add_user_operation(email: &str, id: &str, flow: &str) -> TypedMessage {
    let op = hs::AddUserOperation {
        user: Some(xray_user(VlessUser {
            id: Secret(id.into()),
            email: email.into(),
            flow: flow.into(),
        })),
    };
    TypedMessage {
        r#type: ADD_USER.into(),
        value: op.encode_to_vec(),
    }
}

/// An `AlterInbound` operation that removes a user by email.
pub fn remove_user_operation(email: &str) -> TypedMessage {
    TypedMessage {
        r#type: REMOVE_USER.into(),
        value: hs::RemoveUserOperation {
            email: email.into(),
        }
        .encode_to_vec(),
    }
}

/// Reads the VLESS account of a user the API returned.
pub fn vless_account(user: &User) -> Option<Account> {
    let a = user.account.as_ref()?;
    (a.r#type == VLESS_ACCOUNT)
        .then(|| Account::decode(a.value.as_slice()).ok())
        .flatten()
}
