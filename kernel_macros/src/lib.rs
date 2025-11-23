use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, quote_spanned};
use syn::{parse_macro_input, FnArg, ItemFn, Pat, ReturnType, Type};

const IO_FUTURE_PATH: &str = "::kernel_api::kernel_types::BoxedIoFuture";

#[proc_macro_attribute]
pub fn io_handler(args: TokenStream, input: TokenStream) -> TokenStream {
    if !args.is_empty() {
        return syn::Error::new(Span::call_site(), "#[io_handler] does not accept arguments")
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
            "#[io_handler] expects an async fn",
        ));
    }

    if let Some(abi) = &sig.abi {
        return Err(syn::Error::new_spanned(
            abi,
            "#[io_handler] does not support extern functions; remove the ABI",
        ));
    }

    if let Some(variadic) = &sig.variadic {
        return Err(syn::Error::new_spanned(
            variadic,
            "#[io_handler] does not support variadic parameters",
        ));
    }

    for input in &sig.inputs {
        match input {
            FnArg::Receiver(rec) => {
                return Err(syn::Error::new_spanned(
                    rec,
                    "#[io_handler] only supports free functions (no self receiver)",
                ));
            }
            FnArg::Typed(pat_ty) => {
                if let Type::Reference(ty_ref) = &*pat_ty.ty {
                    return Err(syn::Error::new_spanned(
                        ty_ref,
                        "#[io_handler] handler parameters must be owned types (no references); use Arc<T> etc. instead",
                    ));
                }

                if !matches!(*pat_ty.pat, Pat::Ident(_)) {
                    return Err(syn::Error::new_spanned(
                        &pat_ty.pat,
                        "#[io_handler] parameters must be simple identifiers",
                    ));
                }
            }
        }
    }
    match &sig.output {
        ReturnType::Default => {
            return Err(syn::Error::new_spanned(
                sig,
                "#[io_handler] function must return DriverStatus",
            ));
        }
        ReturnType::Type(_, ty) => {
            let type_str = quote::quote!(#ty).to_string();
            if !type_str.contains("DriverStatus") {
                return Err(syn::Error::new_spanned(
                    ty,
                    "#[io_handler] function must return DriverStatus",
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

    sig.asyncness = None;

    let io_future_type: Type =
        syn::parse_str(IO_FUTURE_PATH).expect("Failed to parse IoFuture path");
    sig.output = ReturnType::Type(Default::default(), Box::new(io_future_type));

    let original_stmts = &body.stmts;

    let new_body = quote_spanned! {body.brace_token.span.join() =>
        {
            ::alloc::boxed::Box::pin(async move {
                #(#original_stmts)*
            })
        }
    };

    quote! {
        #(#attrs)*
        #vis #sig #new_body
    }
}
