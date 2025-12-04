use alloy::{
    primitives::{Address, Bytes, address},
    signers::Signature,
};
use axum::{Json, Router, extract::State, routing::get};
use clap::Parser;
use discv5::{ConfigBuilder, Enr, enr::CombinedKey};
use kona_disc::LocalNode;
use kona_node_service::{NetworkBuilder};
use kona_registry::ROLLUP_CONFIGS;
use libp2p::{Multiaddr, identity::Keypair};
use op_alloy_rpc_types_engine::{OpExecutionPayload, OpNetworkPayloadEnvelope};
use serde::{Deserialize, Serialize};
use ssz::Encode;
use std::{
    borrow::BorrowMut,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[tokio::main]
async fn main() {
    enable_tracing();
    let cli = Cli::parse();
    start(
        &cli.network,
        cli.disc_port,
        cli.gossip_port,
        cli.server_port,
    )
    .await;
}

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    network: String,
    #[arg(short, long)]
    disc_port: u16,
    #[arg(long)]
    #[arg(short, long)]
    gossip_port: u16,
    #[arg(short, long)]
    server_port: u16,
}

async fn start(network: &str, disc_port: u16, gossip_port: u16, server_port: u16) {
    let chain_config = ChainConfig::from(network);

    let gossip = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), gossip_port);
    let mut gossip_addr = Multiaddr::from(gossip.ip());
    gossip_addr.push(libp2p::multiaddr::Protocol::Tcp(gossip.port()));

    let CombinedKey::Secp256k1(k256_key) = CombinedKey::generate_secp256k1() else {
        unreachable!()
    };
    let advertise_ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let disc = LocalNode::new(k256_key, advertise_ip, disc_port, disc_port);
    let disc_listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), disc_port);

    let gossip_key = Keypair::generate_secp256k1();

    let cfg = ROLLUP_CONFIGS
        .get(&chain_config.chain_id)
        .expect("rollup config not found")
        .clone();

    let mut network = NetworkBuilder::new(
        cfg,
        chain_config.unsafe_signer,
        gossip_addr,
        gossip_key,
        disc,
        ConfigBuilder::new(disc_listen.into()).build(),
        None,
    )
    .build()
    .expect("Failed to builder network driver");

    for bootnode in chain_config.bootnodes {
        network
            .discovery
            .borrow_mut()
            .disc
            .borrow_mut()
            .add_enr(bootnode)
            .unwrap();
    }

    // Start the network and get the handler
    let mut handler = network
        .start()
        .await
        .expect("Failed to start network driver");

    let state = Arc::new(RwLock::new(ServerState {
        latest_commitment: None,
        chain_id: chain_config.chain_id,
    }));

    let state_copy = state.clone();

    // Process network events and extract block payloads
    tokio::spawn(async move {
        loop {
            // Also handle ENR discovery events
            tokio::select! {
                Some(enr) = handler.enr_receiver.recv() => {
                    handler.gossip.dial(enr);
                }
                Some(event) = handler.gossip.next() => {
                    if let Some(payload_envelope) = handler.gossip.handle_event(event) {
                        let hash = payload_envelope.payload.block_hash();
                        let number = payload_envelope.payload.block_number();
                        info!("block received: {}", hash);

                        let latest = state_copy
                            .read()
                            .await
                            .latest_commitment
                            .as_ref()
                            .map(|value| value.1)
                            .unwrap_or_default();

                        if number > latest {
                            let commitment = SequencerCommitment::from(payload_envelope);
                            state_copy.write().await.latest_commitment = Some((commitment, number));
                        }
                    }
                }
            }
        }
    });

    let router = Router::new()
        .route("/latest", get(latest_handler))
        .route("/chain_id", get(chain_id_handler))
        .with_state(state);

    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), server_port);
    let listener = tokio::net::TcpListener::bind(server_addr).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}

fn enable_tracing() {
    let env_filter =
        EnvFilter::from_default_env().add_directive("helios_opstack_server".parse().unwrap());

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("subscriber set failed");
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SequencerCommitment {
    data: Bytes,
    signature: Signature,
}

impl From<OpNetworkPayloadEnvelope> for SequencerCommitment {
    fn from(value: OpNetworkPayloadEnvelope) -> Self {
        let parent_root = value.parent_beacon_block_root.unwrap();
        let payload = match value.payload {
            OpExecutionPayload::V1(value) => value.as_ssz_bytes(),
            OpExecutionPayload::V2(value) => value.as_ssz_bytes(),
            OpExecutionPayload::V3(value) => value.as_ssz_bytes(),
            OpExecutionPayload::V4(value) => value.as_ssz_bytes(),
        };

        let data = [parent_root.as_slice(), &payload].concat();

        SequencerCommitment {
            data: data.into(),
            signature: value.signature,
        }
    }
}

#[derive(Clone)]
struct ServerState {
    latest_commitment: Option<(SequencerCommitment, u64)>,
    chain_id: u64,
}

async fn latest_handler(
    State(state): State<Arc<RwLock<ServerState>>>,
) -> Json<Option<SequencerCommitment>> {
    Json(
        state
            .read()
            .await
            .latest_commitment
            .as_ref()
            .map(|value| value.0.clone()),
    )
}

async fn chain_id_handler(State(state): State<Arc<RwLock<ServerState>>>) -> Json<u64> {
    Json(state.read().await.chain_id)
}

struct ChainConfig {
    unsafe_signer: Address,
    chain_id: u64,
    bootnodes: Vec<Enr>,
}

impl From<&str> for ChainConfig {
    fn from(value: &str) -> Self {
        match value {
            "op-mainnet" => ChainConfig {
                unsafe_signer: address!("AAAA45d9549EDA09E70937013520214382Ffc4A2"),
                chain_id: 10,
                bootnodes: Vec::new(),
            },
            "base" => ChainConfig {
                unsafe_signer: address!("Af6E19BE0F9cE7f8afd49a1824851023A8249e8a"),
                chain_id: 8453,
                // retrieved from: https://github.com/base/node/blob/18a9591d2b06ae90885d450e824c75ccd6d8582c/.env.mainnet#L26
                bootnodes: vec![
                    "enr:-J24QNz9lbrKbN4iSmmjtnr7SjUMk4zB7f1krHZcTZx-JRKZd0kA2gjufUROD6T3sOWDVDnFJRvqBBo62zuF-hYCohOGAYiOoEyEgmlkgnY0gmlwhAPniryHb3BzdGFja4OFQgCJc2VjcDI1NmsxoQKNVFlCxh_B-716tTs-h1vMzZkSs1FTu_OYTNjgufplG4N0Y3CCJAaDdWRwgiQG",
                    "enr:-J24QH-f1wt99sfpHy4c0QJM-NfmsIfmlLAMMcgZCUEgKG_BBYFc6FwYgaMJMQN5dsRBJApIok0jFn-9CS842lGpLmqGAYiOoDRAgmlkgnY0gmlwhLhIgb2Hb3BzdGFja4OFQgCJc2VjcDI1NmsxoQJ9FTIv8B9myn1MWaC_2lJ-sMoeCDkusCsk4BYHjjCq04N0Y3CCJAaDdWRwgiQG",
                    "enr:-J24QDXyyxvQYsd0yfsN0cRr1lZ1N11zGTplMNlW4xNEc7LkPXh0NAJ9iSOVdRO95GPYAIc6xmyoCCG6_0JxdL3a0zaGAYiOoAjFgmlkgnY0gmlwhAPckbGHb3BzdGFja4OFQgCJc2VjcDI1NmsxoQJwoS7tzwxqXSyFL7g0JM-KWVbgvjfB8JA__T7yY_cYboN0Y3CCJAaDdWRwgiQG",
                    "enr:-J24QHmGyBwUZXIcsGYMaUqGGSl4CFdx9Tozu-vQCn5bHIQbR7On7dZbU61vYvfrJr30t0iahSqhc64J46MnUO2JvQaGAYiOoCKKgmlkgnY0gmlwhAPnCzSHb3BzdGFja4OFQgCJc2VjcDI1NmsxoQINc4fSijfbNIiGhcgvwjsjxVFJHUstK9L1T8OTKUjgloN0Y3CCJAaDdWRwgiQG",
                    "enr:-J24QG3ypT4xSu0gjb5PABCmVxZqBjVw9ca7pvsI8jl4KATYAnxBmfkaIuEqy9sKvDHKuNCsy57WwK9wTt2aQgcaDDyGAYiOoGAXgmlkgnY0gmlwhDbGmZaHb3BzdGFja4OFQgCJc2VjcDI1NmsxoQIeAK_--tcLEiu7HvoUlbV52MspE0uCocsx1f_rYvRenIN0Y3CCJAaDdWRwgiQG",
                ]
                .iter()
                .map(|v| v.parse().unwrap())
                .collect::<_>(),
            },
            "unichain" => ChainConfig {
                unsafe_signer: address!("0x833C6f278474A78658af91aE8edC926FE33a230e"),
                chain_id: 130,
                bootnodes: vec![
                    "enr:-Iq4QNqqxkwND5YdrKxSVR8RoZHwU6Qa42ff_0XNjD428_n9OTEy3N9iR4uZTfQxACB00fT7Y8__q238kpb6TcsRvw-GAZZoqRJLgmlkgnY0gmlwhDQOHieJc2VjcDI1NmsxoQLqnqr2lfrL5TCQvrelsEEagUWbv25sqsFR5YfudxIKG4N1ZHCCdl8",
                    "enr:-Iq4QBtf4EkiX7NfYxCn6CKIh3ZJqjk70NWS9hajT1k3W7-3ePWBc5-g19tBqYAMWlfSSz3sir024EQc5YH3TAxVY76GAZZopWrWgmlkgnY0gmlwhAOUZK2Jc2VjcDI1NmsxoQN3trHnKYTV1Q4ArpNP_qmCkCIm_pL6UNpCM0wnUNjkBYN1ZHCCdl8",
                ]
                .iter()
                .map(|v| v.parse().unwrap())
                .collect::<_>(),
            },
            _ => panic!("network not recognized"),
        }
    }
}
