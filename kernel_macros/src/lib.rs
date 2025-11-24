use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, quote_spanned};
use syn::{parse_macro_input, FnArg, ItemFn, Pat, ReturnType, Type};

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

    // We still reject manual ABIs because the macro is responsible for applying
    // the correct 'extern "win64"' ABI.
    if let Some(abi) = &sig.abi {
        return Err(syn::Error::new_spanned(
            abi,
            "#[io_handler] applies the ABI automatically; remove the explicit 'extern' declaration",
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

    // 1. Remove async since we are executing strictly inside block_on
    sig.asyncness = None;

    // 2. FORCE EXTERN "win64" ABI
    // This makes the function callable from the Windows Kernel dispatcher.
    sig.abi = Some(syn::parse_str("extern \"win64\"").expect("Failed to parse win64 ABI"));

    // 3. Return Type
    // We do NOT modify sig.output here.
    // `validate_function` confirmed the user wrote `-> DriverStatus`,
    // so we keep that exactly as is.

    let original_stmts = &body.stmts;

    // 4. Transform body to wrap the async block in ::kernel_api::block_on
    let new_body = quote_spanned! {body.brace_token.span.join() =>
        {
            // Execute the future synchronously on this thread
            ::kernel_api::block_on(async move {
                #(#original_stmts)*
            })
        }
    };

    quote! {
        #(#attrs)*
        #vis #sig #new_body
    }
}
