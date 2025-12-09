use netgauze_flow_pkt::FlowInfo;
use std::net::SocketAddr;
use opentelemetry::metrics::Meter;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use crate::flow::renormalization::renormalization::renormalize;

#[derive(Debug, Clone)]
pub struct RenormalizationStats {
    pub received_messages: opentelemetry::metrics::Counter<u64>,
}

impl RenormalizationStats {
    pub fn new(meter: Meter) -> Self {
        let received_messages = meter
            .u64_counter("netgauze.collector.flows.renormalization.received.messages")
            .with_description("Number of flow messages received for renormalization")
            .build();
        Self {
            received_messages,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RenormalizationCommand {
    Shutdown,
}

# [derive(Debug)]
struct RenormalizationActor {
    cmd_rx: mpsc::Receiver<RenormalizationCommand>,
    flow_rx: async_channel::Receiver<(SocketAddr, FlowInfo)>,
    flow_tx: async_channel::Sender<(SocketAddr, FlowInfo)>,
}

impl RenormalizationActor {
    fn new(
        cmd_rx: mpsc::Receiver<RenormalizationCommand>,
        flow_rx: async_channel::Receiver<(SocketAddr, FlowInfo)>,
        flow_tx: async_channel::Sender<(SocketAddr, FlowInfo)>,
    ) -> Self {
        Self { cmd_rx, flow_rx, flow_tx }
    }

    async fn run(mut self) -> anyhow::Result<String> {
        loop {
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(RenormalizationCommand::Shutdown) => {
                            info!("Shutting down flow renormalization actor");

                        }
                        None => {
                            warn!("Flow renormalization actor terminated due to command channel closing");
                        }
                    }
                    return Ok("Renormalization shutdown successfully".to_string());
                }
                flow = self.flow_rx.recv() => {
                    match flow {
                        Ok((peer, flow)) => {
                            // call renormalization processing
                            let renormilized = renormalize(flow);
                            if let Err(err) = self.flow_tx.send((peer, renormilized)).await {
                                error!("Flow renormalization send error: {err}");
                                // TODO: Add stats increment here
                            }
                            else {
                                // TODO: Add stats increment here
                            }
                        }
                        Err(err) => {
                            error!("Shutting down due to Renormalization recv error: {err}");
                            Err(RenormalizationActorError::FlowReceiveError)?;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum RenormalizationActorError {
    RenormalizationChannelClosed,
    FlowReceiveError,
}

impl std::fmt::Display for RenormalizationActorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RenormalizationChannelClosed => write!(f, "Renormalization channel closed"),
            Self::FlowReceiveError => write!(f, "error in flow receive channel"),
        }
    }
}

impl std::error::Error for RenormalizationActorError {}
