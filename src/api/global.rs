// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Process-wide management API registration entrypoint.

use std::sync::{OnceLock, RwLock};

use crate::api::ApiRegister;

static GLOBAL_API_REGISTER: OnceLock<RwLock<Option<ApiRegister>>> = OnceLock::new();

fn global_slot() -> &'static RwLock<Option<ApiRegister>> {
    GLOBAL_API_REGISTER.get_or_init(|| RwLock::new(None))
}

/// Set the process-wide API register used by plugin API registration helpers.
pub fn set_global_api_register(register: Option<ApiRegister>) {
    if let Ok(mut guard) = global_slot().write() {
        *guard = register;
    }
}

/// Return the process-wide API register, when the management API is enabled.
pub fn global_api_register() -> Option<ApiRegister> {
    global_slot().read().ok().and_then(|guard| guard.clone())
}

/// Clear the process-wide API register.
pub fn clear_global_api_register() {
    set_global_api_register(None);
}

#[cfg(test)]
pub(crate) async fn global_api_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static TEST_GLOBAL_API_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    TEST_GLOBAL_API_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}
