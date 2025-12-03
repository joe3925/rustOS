use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, quote_spanned};
use syn::{parse_macro_input, FnArg, ItemFn, Pat, ReturnType, Type};

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

    let output = transform_function(&mut func);

    output.into()
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

    for input in &sig.inputs {
        match input {
            FnArg::Receiver(rec) => {
                return Err(syn::Error::new_spanned(
                    rec,
                    "#[request_handler] only supports free functions (no self receiver)",
                ));
            }
            FnArg::Typed(pat_ty) => {
                if let Type::Reference(ty_ref) = &*pat_ty.ty {
                    return Err(syn::Error::new_spanned(
                        ty_ref,
                        "#[request_handler] handler parameters must be owned types (no references); use Arc<T> etc. instead",
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
                "#[request_handler] function must return DriverStatus",
            ));
        }
        ReturnType::Type(_, ty) => {
            let type_str = quote::quote!(#ty).to_string();
            if !type_str.contains("DriverStatus") {
                return Err(syn::Error::new_spanned(
                    ty,
                    "#[request_handler] function must return DriverStatus",
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

    let ret_ty: Type = match &sig.output {
        ReturnType::Type(_, ty) => (*ty.clone()),
        ReturnType::Default => unreachable!(),
    };

    sig.asyncness = None;
    sig.abi = Some(syn::parse_str("extern \"win64\"").expect("Failed to parse win64 ABI"));
    sig.output = syn::parse_quote!(-> ::kernel_api::async_ffi::FfiFuture<#ret_ty>);

    let original_stmts = &body.stmts;

    let new_body = quote_spanned! {body.brace_token.span.join() =>
        {
            ::kernel_api::async_ffi::FutureExt::into_ffi(
                async move {
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
