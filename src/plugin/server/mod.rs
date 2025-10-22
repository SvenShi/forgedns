/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::plugin::Plugin;

pub mod udp;

pub trait Server: Plugin {
    fn run(&self);
}
