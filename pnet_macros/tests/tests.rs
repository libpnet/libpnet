extern crate compiletest_rs as compiletest;
extern crate pnet_macros;

use compiletest::Config;
use std::path::PathBuf;

enum TestType {
    CompileFail,
    RunPass,
}

fn run_test(name: &str, ty: TestType) {
    use std::env;
    use TestType::*;

    // Set the required target endian environment variable
    let target_endian = if cfg!(target_endian = "little") {
        "little"
    } else {
        "big"
    };
    env::set_var("CARGO_CFG_TARGET_ENDIAN", target_endian);

    let mode = match ty {
        CompileFail => "compile-fail",
        RunPass => "run-pass",
    };
    let file_name = format!("tests/{}/{}.rs", mode, name);

    let mut config = Config::default();
    config.verbose = true;
    config.mode = mode.parse().expect("Invalid mode");
    config.src_base = PathBuf::from(format!("tests/{}", mode));
    config.link_deps(); // Populate config.target_rustcflags with dependencies on the path
    config.clean_rmeta(); // If your tests import the parent crate, this helps with E0464

    let test_paths = compiletest_rs::common::TestPaths {
        file: file_name.into(),
        base: PathBuf::from(format!("tests/{}", mode)),
        relative_dir: PathBuf::new(),
    };
    compiletest_rs::runtest::run(config, &test_paths);
}

fn run_mode(mode: &'static str) {
    let mut config = Config::default();

    config.mode = mode.parse().expect("Invalid mode");
    config.src_base = PathBuf::from(format!("tests/{}", mode));
    config.link_deps(); // Populate config.target_rustcflags with dependencies on the path
    config.clean_rmeta(); // If your tests import the parent crate, this helps with E0464

    compiletest::run_tests(&config);
}

#[test]
fn compile_test() {
    run_mode("compile-fail");
    run_mode("run-pass");
}

mod compile_panic {
    macro_rules! compile_panic {
        ($name:ident, $err:expr) => {
            #[test]
            #[should_panic]
            fn $name() {
                let stderr = ::std::io::stderr();
                stderr.lock();

                super::run_test(stringify!($name), super::TestType::CompileFail);
            }
        };
    }

    compile_panic!(payload_fn2, "unknown attribute: payload");
    compile_panic!(
        endianness_not_specified,
        "endianness must be specified for types of size >= 8"
    );
    compile_panic!(
        length_expr,
        "Only field names, constants, integers, \
                                basic arithmetic expressions (+ - * / %) \
                                and parentheses are allowed in the \"length\" attribute"
    );
    compile_panic!(unnamed_field, "all fields in a packet must be named");
    compile_panic!(no_payload, "#[packet]'s must contain a payload");
    compile_panic!(
        invalid_type,
        "non-primitive field types must specify #[construct_with]"
    );
    compile_panic!(
        length_expr_parentheses,
        "this file contains an un-closed delimiter"
    );
    compile_panic!(multiple_payload, "packet may not have multiple payloads");
    compile_panic!(
        variable_length_fields,
        "variable length field must have #[length = \"\"] or \
                                           #[length_fn = \"\"] attribute"
    );
    compile_panic!(
        length_expr_key,
        "Field name must be a member of the struct and not the field \
                                    itself"
    );

}
