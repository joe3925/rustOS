use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::format_ident;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::visit::Visit;
use syn::Data;
use syn::DeriveInput;
use syn::{
    parse_macro_input, FnArg, GenericParam, ItemFn, Pat, ReturnType, Token, Type, WhereClause,
};

#[derive(Default)]
struct GenericUseCollector {
    idents: std::collections::BTreeSet<String>,
    lifetimes: std::collections::BTreeSet<String>,
}

impl<'ast> Visit<'ast> for GenericUseCollector {
    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        for segment in &node.path.segments {
            self.idents.insert(segment.ident.to_string());
        }
        syn::visit::visit_type_path(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        for segment in &node.segments {
            self.idents.insert(segment.ident.to_string());
        }
        syn::visit::visit_path(self, node);
    }

    fn visit_lifetime(&mut self, node: &'ast syn::Lifetime) {
        self.lifetimes.insert(node.ident.to_string());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestViewKind {
    Shared,
    Mutable,
    Into,
}

struct RequestViewSpec {
    kind: RequestViewKind,
    source: Type,
    target: Type,
    where_clause: Option<WhereClause>,
}

struct RequestViewArgs {
    source: Type,
    target: Type,
    where_clause: Option<WhereClause>,
}

impl Parse for RequestViewArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let source = input.parse()?;
        input.parse::<Token![=>]>().map_err(|_| {
            input.error("expected `=>` between request view source and target types")
        })?;
        let target = input.parse()?;
        let where_clause = if input.peek(Token![where]) {
            Some(input.parse()?)
        } else {
            None
        };

        if !input.is_empty() {
            return Err(input.error("unexpected tokens after request view declaration"));
        }

        Ok(Self {
            source,
            target,
            where_clause,
        })
    }
}

fn request_view_attrs(attrs: &[syn::Attribute]) -> syn::Result<Vec<RequestViewSpec>> {
    let mut specs = Vec::new();

    for attr in attrs {
        let kind = if attr.path().is_ident("request_view") {
            RequestViewKind::Shared
        } else if attr.path().is_ident("request_view_mut") {
            RequestViewKind::Mutable
        } else if attr.path().is_ident("request_into") {
            RequestViewKind::Into
        } else {
            continue;
        };

        let args = attr.parse_args::<RequestViewArgs>()?;
        specs.push(RequestViewSpec {
            kind,
            source: args.source,
            target: args.target,
            where_clause: args.where_clause,
        });
    }

    Ok(specs)
}

fn where_predicates(
    base: Option<&WhereClause>,
    extra: Option<&WhereClause>,
) -> Vec<syn::WherePredicate> {
    let mut predicates = Vec::new();

    if let Some(where_clause) = base {
        predicates.extend(where_clause.predicates.iter().cloned());
    }
    if let Some(where_clause) = extra {
        predicates.extend(where_clause.predicates.iter().cloned());
    }

    predicates
}

fn check_where_clause(predicates: &[syn::WherePredicate]) -> TokenStream2 {
    if predicates.is_empty() {
        quote! {}
    } else {
        quote! { where #(#predicates,)* }
    }
}

fn collect_type_uses(ty: &Type) -> GenericUseCollector {
    let mut collector = GenericUseCollector::default();
    collector.visit_type(ty);
    collector
}

fn collect_predicate_uses(predicate: &syn::WherePredicate) -> GenericUseCollector {
    let mut collector = GenericUseCollector::default();
    collector.visit_where_predicate(predicate);
    collector
}

fn original_generic_names(
    generics: &syn::Generics,
) -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
) {
    let mut idents = std::collections::BTreeSet::new();
    let mut lifetimes = std::collections::BTreeSet::new();

    for param in &generics.params {
        match param {
            GenericParam::Type(param) => {
                idents.insert(param.ident.to_string());
            }
            GenericParam::Const(param) => {
                idents.insert(param.ident.to_string());
            }
            GenericParam::Lifetime(param) => {
                lifetimes.insert(param.lifetime.ident.to_string());
            }
        }
    }

    (idents, lifetimes)
}

fn filtered_impl_generics_and_predicates(
    generics: &syn::Generics,
    source: &Type,
    predicates: &[syn::WherePredicate],
) -> (TokenStream2, Vec<syn::WherePredicate>) {
    let source_uses = collect_type_uses(source);
    let (generic_idents, generic_lifetimes) = original_generic_names(generics);
    let used_idents: std::collections::BTreeSet<_> = source_uses
        .idents
        .intersection(&generic_idents)
        .cloned()
        .collect();
    let used_lifetimes: std::collections::BTreeSet<_> = source_uses
        .lifetimes
        .intersection(&generic_lifetimes)
        .cloned()
        .collect();
    let mut params = Vec::new();

    for param in &generics.params {
        match param {
            GenericParam::Type(param) if used_idents.contains(&param.ident.to_string()) => {
                params.push(quote! { #param });
            }
            GenericParam::Const(param) if used_idents.contains(&param.ident.to_string()) => {
                params.push(quote! { #param });
            }
            GenericParam::Lifetime(param)
                if used_lifetimes.contains(&param.lifetime.ident.to_string()) =>
            {
                params.push(quote! { #param });
            }
            _ => {}
        }
    }

    let impl_generics = if params.is_empty() {
        quote! {}
    } else {
        quote! { <#(#params),*> }
    };

    let filtered_predicates = predicates
        .iter()
        .filter(|predicate| {
            let uses = collect_predicate_uses(predicate);
            let predicate_generic_idents: std::collections::BTreeSet<_> =
                uses.idents.intersection(&generic_idents).collect();
            let predicate_generic_lifetimes: std::collections::BTreeSet<_> =
                uses.lifetimes.intersection(&generic_lifetimes).collect();

            predicate_generic_idents
                .iter()
                .all(|ident| used_idents.contains(*ident))
                && predicate_generic_lifetimes
                    .iter()
                    .all(|lifetime| used_lifetimes.contains(*lifetime))
        })
        .cloned()
        .collect();

    (impl_generics, filtered_predicates)
}

fn request_view_case_items(
    ident: &syn::Ident,
    generics: &syn::Generics,
    spec: &RequestViewSpec,
    index: usize,
) -> (syn::Ident, TokenStream2) {
    let mut generics_with_data = generics.clone();
    generics_with_data
        .params
        .insert(0, syn::parse_quote!('__request_payload_data));
    let (impl_generics_with_data, _, _) = generics_with_data.split_for_impl();
    let (impl_generics, ty_generics, base_where_clause) = generics.split_for_impl();

    let source = &spec.source;
    let target = &spec.target;
    let predicates = where_predicates(generics.where_clause.as_ref(), spec.where_clause.as_ref());
    let (source_impl_generics, source_predicates) =
        filtered_impl_generics_and_predicates(generics, source, &predicates);

    let source_impl_generics_with_data_str = source_impl_generics.to_string();
    let source_impl_generics_with_data = if source_impl_generics_with_data_str.is_empty() {
        quote! { <'__request_payload_data> }
    } else {
        if source_impl_generics_with_data_str.starts_with('<') {
            let inner = &source_impl_generics_with_data_str
                [1..source_impl_generics_with_data_str.len() - 1];
            let inner_tokens: TokenStream2 = inner.parse().unwrap();
            quote! { <'__request_payload_data, #inner_tokens> }
        } else {
            quote! { <'__request_payload_data> }
        }
    };

    let check_where = check_where_clause(&predicates);
    let case_ident = match spec.kind {
        RequestViewKind::Shared => {
            format_ident!("__request_payload_view_case_for_{}_{}", ident, index)
        }
        RequestViewKind::Mutable => {
            format_ident!("__request_payload_view_mut_case_for_{}_{}", ident, index)
        }
        RequestViewKind::Into => unreachable!("request_into is handled separately"),
    };
    let check_ident = match spec.kind {
        RequestViewKind::Shared => {
            format_ident!("__request_payload_view_check_for_{}_{}", ident, index)
        }
        RequestViewKind::Mutable => {
            format_ident!("__request_payload_view_mut_check_for_{}_{}", ident, index)
        }
        RequestViewKind::Into => unreachable!("request_into is handled separately"),
    };

    let (view_bound, check_view_bound, projection_body) = match spec.kind {
        RequestViewKind::Shared => (
            quote! { ::kernel_types::request::RequestPayloadView<'__request_payload_data, #target> },
            quote! { ::kernel_types::request::RequestPayloadView<'__request_payload_data, __RequestViewTarget> },
            quote! {
                let source = unsafe {
                    <#source as ::kernel_types::request::RequestPayload<'__request_payload_data>>::shared_from_raw_parts(parts)
                };
                let target = <#source as ::core::convert::AsRef<#target>>::as_ref(source);
                ::core::option::Option::Some(
                    <#target as ::kernel_types::request::RequestPayload<'__request_payload_data>>::shared_raw_parts(target)
                )
            },
        ),
        RequestViewKind::Mutable => (
            quote! { ::kernel_types::request::RequestPayloadViewMut<'__request_payload_data, #target> },
            quote! { ::kernel_types::request::RequestPayloadViewMut<'__request_payload_data, __RequestViewTarget> },
            quote! {
                let source = unsafe {
                    <#source as ::kernel_types::request::RequestPayload<'__request_payload_data>>::mut_from_raw_parts(parts)
                };
                let target = <#source as ::core::convert::AsMut<#target>>::as_mut(source);
                ::core::option::Option::Some(
                    <#target as ::kernel_types::request::RequestPayload<'__request_payload_data>>::mut_raw_parts(target)
                )
            },
        ),
        RequestViewKind::Into => unreachable!("request_into is handled separately"),
    };

    let items = quote! {
        #[allow(non_camel_case_types)]
        #[doc(hidden)]
        trait #case_ident<'__request_payload_data> {
            unsafe extern "win64" fn request_payload_view_case(
                target_tag: u64,
                parts: ::kernel_types::request::RequestPayloadRawParts,
            ) -> ::core::option::Option<::kernel_types::request::RequestPayloadRawParts>;
        }

        impl #impl_generics_with_data #case_ident<'__request_payload_data> for #ident #ty_generics #base_where_clause {
            #[inline]
            default unsafe extern "win64" fn request_payload_view_case(
                _target_tag: u64,
                _parts: ::kernel_types::request::RequestPayloadRawParts,
            ) -> ::core::option::Option<::kernel_types::request::RequestPayloadRawParts> {
                ::core::option::Option::None
            }
        }

        impl #source_impl_generics_with_data #case_ident<'__request_payload_data> for #source
        where
            #source: #view_bound,
            #target: ::kernel_types::request::RequestPayload<'__request_payload_data>,
            #(#source_predicates,)*
        {
            #[inline]
            unsafe extern "win64" fn request_payload_view_case(
                target_tag: u64,
                parts: ::kernel_types::request::RequestPayloadRawParts,
            ) -> ::core::option::Option<::kernel_types::request::RequestPayloadRawParts> {
                if target_tag
                    != <#target as ::kernel_types::request::RequestPayload<'__request_payload_data>>::runtime_tag()
                {
                    return ::core::option::Option::None;
                }

                #projection_body
            }
        }

        #[allow(non_snake_case, dead_code)]
        fn #check_ident #impl_generics () #check_where {
            fn assert_request_view<'__request_payload_data, __RequestViewSource, __RequestViewTarget>()
            where
                __RequestViewSource: ?Sized + #check_view_bound,
                __RequestViewTarget: ?Sized + ::kernel_types::request::RequestPayload<'__request_payload_data>,
            {
            }

            assert_request_view::<#source, #target>();
        }
    };

    (case_ident, items)
}

fn request_into_case_items(
    ident: &syn::Ident,
    generics: &syn::Generics,
    spec: &RequestViewSpec,
    index: usize,
) -> (syn::Ident, TokenStream2) {
    let mut generics_with_data = generics.clone();
    generics_with_data
        .params
        .insert(0, syn::parse_quote!('__request_payload_data));
    let (impl_generics_with_data, _, _) = generics_with_data.split_for_impl();
    let (impl_generics, ty_generics, base_where_clause) = generics.split_for_impl();

    let source = &spec.source;
    let target = &spec.target;
    let predicates = where_predicates(generics.where_clause.as_ref(), spec.where_clause.as_ref());
    let (source_impl_generics, source_predicates) =
        filtered_impl_generics_and_predicates(generics, source, &predicates);

    let source_impl_generics_with_data_str = source_impl_generics.to_string();
    let source_impl_generics_with_data = if source_impl_generics_with_data_str.is_empty() {
        quote! { <'__request_payload_data> }
    } else {
        if source_impl_generics_with_data_str.starts_with('<') {
            let inner = &source_impl_generics_with_data_str
                [1..source_impl_generics_with_data_str.len() - 1];
            let inner_tokens: TokenStream2 = inner.parse().unwrap();
            quote! { <'__request_payload_data, #inner_tokens> }
        } else {
            quote! { <'__request_payload_data> }
        }
    };

    let check_where = check_where_clause(&predicates);
    let case_ident = format_ident!("__request_payload_into_case_for_{}_{}", ident, index);
    let check_ident = format_ident!("__request_payload_into_check_for_{}_{}", ident, index);

    let items = quote! {
        #[allow(non_camel_case_types)]
        #[doc(hidden)]
        trait #case_ident<'__request_payload_data> {
            unsafe extern "win64" fn can_request_payload_into_case(
                target_tag: u64,
                parts: ::kernel_types::request::RequestPayloadRawParts,
            ) -> bool;

            unsafe extern "win64" fn request_payload_into_case(
                target_tag: u64,
                parts: ::kernel_types::request::RequestPayloadRawParts,
                out: *mut ::kernel_types::request::RequestData<'__request_payload_data>,
            ) -> bool;
        }

        impl #impl_generics_with_data #case_ident<'__request_payload_data> for #ident #ty_generics #base_where_clause {
            #[inline]
            default unsafe extern "win64" fn can_request_payload_into_case(
                _target_tag: u64,
                _parts: ::kernel_types::request::RequestPayloadRawParts,
            ) -> bool {
                false
            }

            #[inline]
            default unsafe extern "win64" fn request_payload_into_case(
                _target_tag: u64,
                _parts: ::kernel_types::request::RequestPayloadRawParts,
                _out: *mut ::kernel_types::request::RequestData<'__request_payload_data>,
            ) -> bool {
                false
            }
        }

        impl #source_impl_generics_with_data #case_ident<'__request_payload_data> for #source
        where
            #source: ::kernel_types::request::RequestPayloadInto<'__request_payload_data, #target>,
            #target: ::kernel_types::request::RequestPayload<'__request_payload_data>,
            #(#source_predicates,)*
        {
            #[inline]
            unsafe extern "win64" fn can_request_payload_into_case(
                target_tag: u64,
                _parts: ::kernel_types::request::RequestPayloadRawParts,
            ) -> bool {
                target_tag == <#target as ::kernel_types::request::RequestPayload<'__request_payload_data>>::runtime_tag()
            }

            #[inline]
            unsafe extern "win64" fn request_payload_into_case(
                target_tag: u64,
                parts: ::kernel_types::request::RequestPayloadRawParts,
                out: *mut ::kernel_types::request::RequestData<'__request_payload_data>,
            ) -> bool {
                if target_tag
                    != <#target as ::kernel_types::request::RequestPayload<'__request_payload_data>>::runtime_tag()
                {
                    return false;
                }

                let source = unsafe { ::core::ptr::read(parts.data as *const #source) };
                let target = <#source as ::core::convert::Into<#target>>::into(source);
                unsafe {
                    ::core::ptr::write(out, ::kernel_types::request::RequestData::from_t(target));
                }
                true
            }
        }

        #[allow(non_snake_case, dead_code)]
        fn #check_ident #impl_generics () #check_where {
            fn assert_request_into<'__request_payload_data, __RequestIntoSource, __RequestIntoTarget>()
            where
                __RequestIntoSource:
                    ::kernel_types::request::RequestPayloadInto<'__request_payload_data, __RequestIntoTarget>,
                __RequestIntoTarget: ::kernel_types::request::RequestPayload<'__request_payload_data>,
            {
            }

            assert_request_into::<#source, #target>();
        }
    };

    (case_ident, items)
}

fn repr_kinds(attrs: &[syn::Attribute]) -> Vec<String> {
    let mut out = Vec::new();

    for attr in attrs {
        if !attr.path().is_ident("repr") {
            continue;
        }

        let _ = attr.parse_nested_meta(|meta| {
            if let Some(ident) = meta.path.get_ident() {
                out.push(ident.to_string());
            }
            Ok(())
        });
    }

    out
}

fn has_struct_layout_repr(attrs: &[syn::Attribute]) -> bool {
    let reprs = repr_kinds(attrs);

    for repr in reprs {
        if repr == "C" || repr == "transparent" {
            return true;
        }
    }

    false
}

fn has_enum_layout_repr(attrs: &[syn::Attribute]) -> bool {
    let reprs = repr_kinds(attrs);

    for repr in reprs {
        match repr.as_str() {
            "C" | "u8" | "u16" | "u32" | "u64" | "usize" | "i8" | "i16" | "i32" | "i64"
            | "isize" => return true,
            _ => {}
        }
    }

    false
}

#[proc_macro_derive(
    RequestPayload,
    attributes(request_view, request_view_mut, request_into)
)]
pub fn derive_request_payload(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let request_views = match request_view_attrs(&input.attrs) {
        Ok(views) => views,
        Err(err) => return err.to_compile_error().into(),
    };

    let needs_ffi_safe = match &input.data {
        Data::Union(_) => {
            return syn::Error::new_spanned(
                &input.ident,
                "RequestPayload derive does not support unions",
            )
            .to_compile_error()
            .into();
        }
        Data::Struct(_) => !has_struct_layout_repr(&input.attrs),
        Data::Enum(_) => !has_enum_layout_repr(&input.attrs),
    };

    let ident = input.ident;
    let generics = input.generics;
    let (_, ty_generics, where_clause) = generics.split_for_impl();
    let mut request_view_case_items_out = Vec::new();
    let mut shared_case_idents = Vec::new();
    let mut mut_case_idents = Vec::new();
    let mut into_case_idents = Vec::new();

    for (index, spec) in request_views.iter().enumerate() {
        let (case_ident, items) = match spec.kind {
            RequestViewKind::Shared | RequestViewKind::Mutable => {
                request_view_case_items(&ident, &generics, spec, index)
            }
            RequestViewKind::Into => request_into_case_items(&ident, &generics, spec, index),
        };
        match spec.kind {
            RequestViewKind::Shared => shared_case_idents.push(case_ident),
            RequestViewKind::Mutable => mut_case_idents.push(case_ident),
            RequestViewKind::Into => into_case_idents.push(case_ident),
        }
        request_view_case_items_out.push(items);
    }

    let (impl_generics, _, _) = generics.split_for_impl();

    let ffi_safe_check_item = if needs_ffi_safe {
        let helper_ident = format_ident!("__request_payload_ffi_safe_check_for_{}", ident);

        quote! {
            #[allow(non_snake_case, dead_code)]
            fn #helper_ident #impl_generics () #where_clause {
                fn assert_impl<T: ::kernel_types::request::FfiSafe>() {}
                assert_impl::<#ident #ty_generics>();
            }
        }
    } else {
        quote! {}
    };

    let mut generics_with_data = generics.clone();
    generics_with_data
        .params
        .insert(0, syn::parse_quote!('__request_payload_data));
    let (impl_generics_with_data, _, _) = generics_with_data.split_for_impl();
    let mut where_clause_with_data = where_clause.cloned().unwrap_or_else(|| syn::WhereClause {
        where_token: syn::parse_quote!(where),
        predicates: syn::punctuated::Punctuated::new(),
    });
    where_clause_with_data
        .predicates
        .push(syn::parse_quote!(Self: '__request_payload_data));

    let shared_view_method = if shared_case_idents.is_empty() {
        quote! {}
    } else {
        quote! {
            #[inline]
            unsafe extern "win64" fn shared_view_raw_parts(
                target_tag: u64,
                parts: ::kernel_types::request::RequestPayloadRawParts,
            ) -> ::core::option::Option<::kernel_types::request::RequestPayloadRawParts> {
                #(
                    if let ::core::option::Option::Some(target_parts) = unsafe {
                        <Self as #shared_case_idents<'__request_payload_data>>::request_payload_view_case(
                            target_tag,
                            parts,
                        )
                    } {
                        return ::core::option::Option::Some(target_parts);
                    }
                )*

                ::core::option::Option::None
            }
        }
    };

    let mut_view_method = if mut_case_idents.is_empty() {
        quote! {}
    } else {
        quote! {
            #[inline]
            unsafe extern "win64" fn mut_view_raw_parts(
                target_tag: u64,
                parts: ::kernel_types::request::RequestPayloadRawParts,
            ) -> ::core::option::Option<::kernel_types::request::RequestPayloadRawParts> {
                #(
                    if let ::core::option::Option::Some(target_parts) = unsafe {
                        <Self as #mut_case_idents<'__request_payload_data>>::request_payload_view_case(
                            target_tag,
                            parts,
                        )
                    } {
                        return ::core::option::Option::Some(target_parts);
                    }
                )*

                ::core::option::Option::None
            }
        }
    };

    let into_method = if into_case_idents.is_empty() {
        quote! {}
    } else {
        quote! {
            #[inline]
            unsafe extern "win64" fn can_into_request_data(
                target_tag: u64,
                parts: ::kernel_types::request::RequestPayloadRawParts,
            ) -> bool {
                #(
                    if unsafe {
                        <Self as #into_case_idents<'__request_payload_data>>::can_request_payload_into_case(
                            target_tag,
                            parts,
                        )
                    } {
                        return true;
                    }
                )*

                false
            }

            #[inline]
            unsafe extern "win64" fn into_request_data(
                target_tag: u64,
                parts: ::kernel_types::request::RequestPayloadRawParts,
                out: *mut ::kernel_types::request::RequestData<'__request_payload_data>,
            ) -> bool {
                #(
                    if unsafe {
                        <Self as #into_case_idents<'__request_payload_data>>::request_payload_into_case(
                            target_tag,
                            parts,
                            out,
                        )
                    } {
                        return true;
                    }
                )*

                false
            }
        }
    };

    quote! {
        #ffi_safe_check_item
        #(#request_view_case_items_out)*

        unsafe impl #impl_generics_with_data ::kernel_types::request::RequestPayload<'__request_payload_data>
            for #ident #ty_generics #where_clause_with_data
        {
            #[inline]
            extern "win64" fn runtime_tag() -> u64 {
                ::kernel_types::request::type_tag::<Self>()
            }

            #[inline]
            extern "win64" fn static_size() -> ::core::option::Option<usize> {
                ::core::option::Option::Some(::core::mem::size_of::<Self>())
            }

            #[inline]
            extern "win64" fn shared_raw_parts(
                payload: &Self,
            ) -> ::kernel_types::request::RequestPayloadRawParts {
                ::kernel_types::request::RequestPayloadRawParts {
                    data: payload as *const Self as *mut u8,
                    metadata: 0,
                    bytes: ::core::mem::size_of::<Self>(),
                }
            }

            #[inline]
            extern "win64" fn mut_raw_parts(
                payload: &mut Self,
            ) -> ::kernel_types::request::RequestPayloadRawParts {
                ::kernel_types::request::RequestPayloadRawParts {
                    data: payload as *mut Self as *mut u8,
                    metadata: 0,
                    bytes: ::core::mem::size_of::<Self>(),
                }
            }

            #[inline]
            unsafe extern "win64" fn shared_from_raw_parts<'payload>(
                parts: ::kernel_types::request::RequestPayloadRawParts,
            ) -> &'payload Self {
                unsafe { &*(parts.data as *const Self) }
            }

            #[inline]
            unsafe extern "win64" fn mut_from_raw_parts<'payload>(
                parts: ::kernel_types::request::RequestPayloadRawParts,
            ) -> &'payload mut Self {
                unsafe { &mut *(parts.data as *mut Self) }
            }

            #shared_view_method
            #mut_view_method
            #into_method
        }
    }
    .into()
}
#[proc_macro_attribute]
pub fn request_handler(args: TokenStream, input: TokenStream) -> TokenStream {
    if !args.is_empty() {
        return syn::Error::new(
            Span::call_site(),
            "#[request_handler] does not accept arguments",
        )
        .to_compile_error()
        .into();
    }

    let mut func = parse_macro_input!(input as ItemFn);

    if let Err(e) = validate_function(&func) {
        return e.to_compile_error().into();
    }

    transform_function(&mut func).into()
}

/// Check if a type is `&mut RequestHandle`
fn type_is_mut_ref_request_handle(ty: &Type) -> bool {
    match ty {
        Type::Reference(r) => r.mutability.is_some() && type_is_request_handle_path(&r.elem),
        Type::Paren(p) => type_is_mut_ref_request_handle(&p.elem),
        Type::Group(g) => type_is_mut_ref_request_handle(&g.elem),
        _ => false,
    }
}

/// Check if a type path is RequestHandle
fn type_is_request_handle_path(ty: &Type) -> bool {
    match ty {
        Type::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident == "RequestHandle")
            .unwrap_or(false),
        Type::Paren(p) => type_is_request_handle_path(&p.elem),
        Type::Group(g) => type_is_request_handle_path(&g.elem),
        _ => false,
    }
}

/// Find the RequestHandle parameter and return its identifier
fn find_request_handle_param(sig: &syn::Signature) -> Option<syn::Ident> {
    for arg in sig.inputs.iter() {
        let FnArg::Typed(pat_ty) = arg else { continue };
        let Pat::Ident(pat_ident) = &*pat_ty.pat else {
            continue;
        };

        if type_is_mut_ref_request_handle(&pat_ty.ty) {
            return Some(pat_ident.ident.clone());
        }
    }
    None
}

fn validate_function(func: &ItemFn) -> syn::Result<()> {
    let sig = &func.sig;

    if sig.asyncness.is_none() {
        return Err(syn::Error::new_spanned(
            sig.fn_token,
            "#[request_handler] expects an async fn",
        ));
    }

    if let Some(abi) = &sig.abi {
        return Err(syn::Error::new_spanned(
            abi,
            "#[request_handler] applies the ABI automatically; remove the explicit 'extern' declaration",
        ));
    }

    if let Some(variadic) = &sig.variadic {
        return Err(syn::Error::new_spanned(
            variadic,
            "#[request_handler] does not support variadic parameters",
        ));
    }

    // Check that there's at least one &mut RequestHandle parameter
    let has_request_handle = find_request_handle_param(sig).is_some();
    if !has_request_handle {
        return Err(syn::Error::new_spanned(
            sig,
            "#[request_handler] requires a &mut RequestHandle parameter",
        ));
    }

    for input in &sig.inputs {
        match input {
            FnArg::Receiver(rec) => {
                return Err(syn::Error::new_spanned(
                    rec,
                    "#[request_handler] only supports free functions (no self receiver)",
                ));
            }
            FnArg::Typed(pat_ty) => {
                // Allow &mut RequestHandle
                if type_is_mut_ref_request_handle(&pat_ty.ty) {
                    continue;
                }

                // Allow shared refs to Arc<_>; disallow other reference types
                if let Type::Reference(ty_ref) = &*pat_ty.ty {
                    if type_is_request_handle_path(&ty_ref.elem) {
                        return Err(syn::Error::new_spanned(
                            ty_ref,
                            "#[request_handler] RequestHandle must be passed as &mut RequestHandle",
                        ));
                    }
                    if type_is_arc(&ty_ref.elem) {
                        continue;
                    }
                    return Err(syn::Error::new_spanned(
                    ty_ref,
                    "#[request_handler] handler parameters must be owned types; only &Arc<T> references are allowed",
                ));
                }

                if !matches!(*pat_ty.pat, Pat::Ident(_)) {
                    return Err(syn::Error::new_spanned(
                        &pat_ty.pat,
                        "#[request_handler] parameters must be simple identifiers",
                    ));
                }
            }
        }
    }

    match &sig.output {
        ReturnType::Default => {
            return Err(syn::Error::new_spanned(
                sig,
                "#[request_handler] function must return DriverStep",
            ));
        }
        ReturnType::Type(_, ty) => {
            let type_str = quote::quote!(#ty).to_string();
            if !type_str.contains("DriverStep") {
                return Err(syn::Error::new_spanned(
                    ty,
                    "#[request_handler] function must return DriverStep",
                ));
            }
        }
    }

    Ok(())
}

fn transform_function(func: &mut ItemFn) -> TokenStream2 {
    let attrs = &func.attrs;
    let vis = &func.vis;
    let sig = &mut func.sig;
    let body = &func.block;

    let fn_ident = sig.ident.clone();
    let obj_expr = choose_object_id_expr(sig);

    // Remove async keyword
    sig.asyncness = None;
    sig.abi = Some(syn::parse_str("extern \"win64\"").expect("Failed to parse win64 ABI"));

    // Set the return type to FfiFuture<DriverStep>
    sig.output = syn::parse_quote!(
        -> ::kernel_api::async_ffi::FfiFuture< ::kernel_api::pnp::DriverStep>
    );

    let original_stmts = &body.stmts;

    let new_body = quote! {
        {
            ::kernel_api::async_ffi::FutureExt::into_ffi(
                async move {
                    let _bench_span = {
                        let __obj: u64 = #obj_expr;
                        ::kernel_api::benchmark::span(
                            stringify!(#fn_ident),
                            ::kernel_api::benchmark::object_id(__obj),
                        )
                    };

                    #(#original_stmts)*
                }
            )
        }
    };

    quote! {
        #(#attrs)*
        #vis #sig #new_body
    }
}

fn choose_object_id_expr(sig: &syn::Signature) -> TokenStream2 {
    for arg in sig.inputs.iter() {
        let FnArg::Typed(pat_ty) = arg else { continue };
        let Pat::Ident(pat_ident) = &*pat_ty.pat else {
            continue;
        };
        let ident = &pat_ident.ident;

        if type_is_arc(&pat_ty.ty) {
            return quote!(::alloc::sync::Arc::as_ptr(&#ident) as usize as u64);
        }

        return quote!(::core::ptr::addr_of!(#ident) as usize as u64);
    }

    quote!(0u64)
}

fn type_is_arc(ty: &Type) -> bool {
    match ty {
        Type::Reference(r) => type_is_arc(&r.elem),
        Type::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident == "Arc")
            .unwrap_or(false),
        Type::Paren(p) => type_is_arc(&p.elem),
        Type::Group(g) => type_is_arc(&g.elem),
        _ => false,
    }
}
