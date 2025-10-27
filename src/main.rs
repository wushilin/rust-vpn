mod client;
mod config;
mod crypto;
mod server;
mod tunnel;

use clap::Parser;
use config::{Cli, Commands, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Parse command line arguments
    let cli = Cli::parse();

    match cli.command {
        Commands::Server(args) => {
            log::info!("Running in server mode");
            let config = Config::from_server_args(&args)?;
            server::run_server(args.listen_addr, args.port, config).await?;
        }
        Commands::Client(args) => {
            log::info!("Running in client mode");
            let config = Config::from_client_args(&args)?;
            client::run_client(args.server, args.port, config).await?;
        }
    }

    Ok(())
}
