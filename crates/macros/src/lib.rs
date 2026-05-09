// SPDX-FileCopyrightText: 2026 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use proc_macro::TokenStream;
use quote::quote;
use syn::{Fields, ItemStruct, LitStr, parse_macro_input};

/// Register an empty plugin factory struct with the OxiDNS inventory.
///
/// Supported forms:
///
/// ```ignore
/// #[plugin_factory("cache")]
/// pub struct CacheFactory;
///
/// #[plugin_factory("sequence")]
/// pub struct SequenceFactory {}
/// ```
#[proc_macro_attribute]
pub fn plugin_factory(attr: TokenStream, item: TokenStream) -> TokenStream {
    let plugin_type = parse_macro_input!(attr as LitStr);
    let item_struct = parse_macro_input!(item as ItemStruct);
    let ident = &item_struct.ident;

    let factory_ctor = match &item_struct.fields {
        Fields::Unit => quote! { #ident },
        Fields::Named(fields) if fields.named.is_empty() => quote! { #ident {} },
        _ => {
            return syn::Error::new_spanned(
                &item_struct,
                "#[plugin_factory] only supports unit structs or empty braced structs; use register_plugin_factory! for factories with state or custom constructors",
            )
            .to_compile_error()
            .into();
        }
    };

    quote! {
        #item_struct

        inventory::submit! {
            crate::plugin::FactoryRegistration {
                plugin_type: #plugin_type,
                module_path: module_path!(),
                constructor: || -> Box<dyn crate::plugin::PluginFactory> {
                    Box::new(#factory_ctor)
                },
            }
        }
    }
    .into()
}
