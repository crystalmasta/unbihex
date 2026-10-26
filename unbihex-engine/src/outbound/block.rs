use super::{BoxStream, Outbound, PacketStream};
use crate::error::{Error, Result};
use crate::session::Session;

/// Refuses every connection.
pub struct BlockOutbound {
    tag: String,
}

impl BlockOutbound {
    /// Creates the outbound.
    pub fn new(tag: &str) -> Self {
        BlockOutbound {
            tag: tag.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl Outbound for BlockOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn is_block(&self) -> bool {
        true
    }
    async fn connect_tcp(&self, _sess: &Session) -> Result<BoxStream> {
        Err(Error::Blocked)
    }
    async fn connect_udp(&self, _sess: &Session) -> Result<Box<dyn PacketStream>> {
        Err(Error::Blocked)
    }
}
