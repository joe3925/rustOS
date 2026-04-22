use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{Data, DeriveInput, FnArg, ItemFn, Pat, ReturnType, Type, parse_macro_input};

#[proc_macro_derive(RequestPayload)]
pub fn derive_request_payload(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    if matches!(input.data, Data::Union(_)) {
        return syn::Error::new_spanned(
            input.ident,
            "RequestPayload derive does not support unions",
        )
        .to_compile_error()
        .into();
    }

    let ident = input.ident;
    let generics = input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        unsafe impl #impl_generics ::kernel_types::request::RequestPayload for #ident #ty_generics #where_clause {
            #[inline]
            fn runtime_tag() -> u64 {
                ::kernel_types::request::type_tag::<Self>()
            }

            #[inline]
            fn static_size() -> ::core::option::Option<usize> {
                ::core::option::Option::Some(::core::mem::size_of::<Self>())
            }

            #[inline]
            fn shared_raw_parts(payload: &Self) -> ::kernel_types::request::RequestPayloadRawParts {
                ::kernel_types::request::RequestPayloadRawParts {
                    data: payload as *const Self as *mut u8,
                    metadata: 0,
                    bytes: ::core::mem::size_of::<Self>(),
                }
            }

            #[inline]
            fn mut_raw_parts(payload: &mut Self) -> ::kernel_types::request::RequestPayloadRawParts {
                ::kernel_types::request::RequestPayloadRawParts {
                    data: payload as *mut Self as *mut u8,
                    metadata: 0,
                    bytes: ::core::mem::size_of::<Self>(),
                }
            }

            #[inline]
            unsafe fn shared_from_raw_parts<'payload>(
                parts: ::kernel_types::request::RequestPayloadRawParts,
            ) -> &'payload Self {
                unsafe { &*(parts.data as *const Self) }
            }

            #[inline]
            unsafe fn mut_from_raw_parts<'payload>(
                parts: ::kernel_types::request::RequestPayloadRawParts,
            ) -> &'payload mut Self {
                unsafe { &mut *(parts.data as *mut Self) }
            }
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

    let _fn_ident = sig.ident.clone();
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
                        // ::kernel_api::benchmark::span(
                        //     stringify!(#fn_ident),
                        //     ::kernel_api::benchmark::object_id(__obj),
                        // )
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
