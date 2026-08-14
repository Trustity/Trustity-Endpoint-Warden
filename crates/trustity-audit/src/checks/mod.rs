mod network;
mod permissions;
mod persistence;
mod secrets;

use crate::cli::Cli;
use crate::finding::Finding;

pub fn run_all(cli: &Cli) -> Vec<Finding> {
    let mut out = Vec::new();
    if !cli.skip_persistence {
        out.extend(persistence::audit());
    }
    if !cli.skip_network {
        out.extend(network::audit());
    }
    if !cli.skip_permissions {
        out.extend(permissions::audit());
    }
    if !cli.skip_secrets {
        out.extend(secrets::audit());
    }
    out
}
