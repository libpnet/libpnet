extern crate pnet_macros;
extern crate syntex;

enum TestType {
    CompileFail,
    RunPass,
}

fn run_test(name: &str, ty: TestType) {
    use std::env;
    use std::fs::File;
    use std::io::prelude::*;
    use TestType::*;

    // Set the required target endian environment variable
    let target_endian = if cfg!(target_endian = "little") {
        "little"
    } else {
        "big"
    };
    env::set_var("CARGO_CFG_TARGET_ENDIAN", target_endian);

    let path = match ty {
        CompileFail => "compile-fail",
        RunPass => "run-pass",
    };
    let file_name = format!("tests/{}/{}.rs", path, name);

    let mut f = File::open(&file_name).unwrap();

    let mut src = String::new();
    f.read_to_string(&mut src).unwrap();

    let mut registry = syntex::Registry::new();
    pnet_macros::register(&mut registry);

    let res = registry.expand_str(name, &file_name, &src);
    match ty {
        CompileFail => {
            if res.is_ok() {
                panic!(format!("unexpected success: {}", file_name));
            }
        }
        RunPass => {
            res.unwrap();
        }
    }
}

mod run_pass {
    macro_rules! run_pass {
        ($name:ident) => {
            #[test]
            fn $name() {
                ::run_test(stringify!($name), super::TestType::RunPass);
            }
        };
    }

    run_pass!(length_expr);
    run_pass!(packet_in_packet);
    run_pass!(min_packet_size);
    run_pass!(get_variable_length_field);
    run_pass!(mqtt);
    run_pass!(variable_length_fields);
    run_pass!(packet_size);
    run_pass!(payload_fn);
}

mod compile_fail {
    macro_rules! compile_fail {
        ($name:ident, $err:expr) => {
            #[test]
            #[should_panic]
            fn $name() {
                let stderr = ::std::io::stderr();
                stderr.lock();

                ::run_test(stringify!($name), super::TestType::CompileFail);
            }
        };
    }

    compile_fail!(payload_fn2, "unknown attribute: payload");
    compile_fail!(
        endianness_not_specified,
        "endianness must be specified for types of size >= 8"
    );
    compile_fail!(
        length_expr,
        "Only field names, constants, integers, \
                                basic arithmetic expressions (+ - * / %) \
                                and parentheses are allowed in the \"length\" attribute"
    );
    compile_fail!(unnamed_field, "all fields in a packet must be named");
    compile_fail!(must_be_pub, "#[packet] structs must be public");
    compile_fail!(no_payload, "#[packet]'s must contain a payload");
    compile_fail!(
        invalid_type,
        "non-primitive field types must specify #[construct_with]"
    );
    compile_fail!(
        length_expr_parentheses,
        "this file contains an un-closed delimiter"
    );
    compile_fail!(multiple_payload, "packet may not have multiple payloads");
    compile_fail!(
        variable_length_fields,
        "variable length field must have #[length = \"\"] or \
                                           #[length_fn = \"\"] attribute"
    );
    compile_fail!(
        length_expr_key,
        "Field name must be a member of the struct and not the field \
                                    itself"
    );
}
