/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Operating system service management commands.

use crate::core::error::{DnsError, Result};
use crate::core::{ServiceCommand, ServiceInstallOptions, ServiceOptions};
use service_manager::{
    RestartPolicy, ServiceInstallCtx, ServiceLabel, ServiceLevel, ServiceManager, ServiceStartCtx,
    ServiceStopCtx, ServiceUninstallCtx, native_service_manager,
};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const SERVICE_LABEL: &str = "forgedns";

pub fn run(options: ServiceOptions) -> Result<()> {
    match options.command {
        ServiceCommand::Install(install) => install_service(install),
        ServiceCommand::Start => start_service(),
        ServiceCommand::Stop => stop_service(),
        ServiceCommand::Uninstall => uninstall_service(),
    }
}

fn install_service(options: ServiceInstallOptions) -> Result<()> {
    let working_dir = normalize_working_dir(&options.working_dir)?;
    let config_path = normalize_config_path(&options.config, &working_dir)?;
    let program = std::env::current_exe()
        .map_err(|err| DnsError::runtime(format!("Failed to resolve current executable: {err}")))?;

    let mut manager = native_service_manager().map_err(|err| {
        DnsError::runtime(format!("Failed to detect native service manager: {err}"))
    })?;
    manager
        .set_level(ServiceLevel::System)
        .map_err(|err| DnsError::runtime(format!("Failed to set service level: {err}")))?;

    let ctx = ServiceInstallCtx {
        label: service_label()?,
        program,
        args: vec![
            OsString::from("start"),
            OsString::from("-c"),
            config_path.into_os_string(),
            OsString::from("-d"),
            working_dir.clone().into_os_string(),
        ],
        contents: None,
        username: None,
        working_directory: Some(working_dir),
        environment: None,
        autostart: true,
        restart_policy: RestartPolicy::Always { delay_secs: None },
    };
    manager
        .install(ctx)
        .map_err(|err| DnsError::runtime(format!("Failed to install service: {err}")))?;
    Ok(())
}

fn start_service() -> Result<()> {
    let manager = service_manager()?;
    manager
        .start(ServiceStartCtx {
            label: service_label()?,
        })
        .map_err(|err| DnsError::runtime(format!("Failed to start service: {err}")))?;
    Ok(())
}

fn stop_service() -> Result<()> {
    let manager = service_manager()?;
    manager
        .stop(ServiceStopCtx {
            label: service_label()?,
        })
        .map_err(|err| DnsError::runtime(format!("Failed to stop service: {err}")))?;
    Ok(())
}

fn uninstall_service() -> Result<()> {
    let manager = service_manager()?;
    manager
        .uninstall(ServiceUninstallCtx {
            label: service_label()?,
        })
        .map_err(|err| DnsError::runtime(format!("Failed to uninstall service: {err}")))?;
    Ok(())
}

fn service_manager() -> Result<Box<dyn ServiceManager>> {
    let mut manager = native_service_manager().map_err(|err| {
        DnsError::runtime(format!("Failed to detect native service manager: {err}"))
    })?;
    manager
        .set_level(ServiceLevel::System)
        .map_err(|err| DnsError::runtime(format!("Failed to set service level: {err}")))?;
    Ok(manager)
}

fn service_label() -> Result<ServiceLabel> {
    SERVICE_LABEL
        .parse()
        .map_err(|err| DnsError::runtime(format!("Invalid service label '{SERVICE_LABEL}': {err}")))
}

fn normalize_working_dir(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(DnsError::config(format!(
            "service install working directory must be absolute: {}",
            path.display()
        )));
    }
    std::fs::create_dir_all(path).map_err(|err| {
        DnsError::runtime(format!(
            "Failed to create working directory {}: {}",
            path.display(),
            err
        ))
    })?;
    path.canonicalize().map_err(|err| {
        DnsError::runtime(format!(
            "Failed to canonicalize working directory {}: {}",
            path.display(),
            err
        ))
    })
}

fn normalize_config_path(path: &Path, working_dir: &Path) -> Result<PathBuf> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        working_dir.join(path)
    };
    candidate.canonicalize().map_err(|err| {
        DnsError::runtime(format!(
            "Failed to canonicalize config path {}: {}",
            candidate.display(),
            err
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_working_dir_rejects_relative_paths() {
        let err = normalize_working_dir(Path::new("relative/path")).expect_err("should fail");
        assert!(err.to_string().contains("must be absolute"));
    }
}
