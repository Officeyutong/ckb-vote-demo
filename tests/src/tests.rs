use ckb_testtool::context::Context;

use crate::Loader;

fn prepare() {
    
}

#[test]
fn test_correct_signature() {
    let mut ctx = Context::default();
    let loader = Loader::default();
    let verifier_bin = loader.load_binary("ring-signature-verify");
    let out_point = ctx.deploy_cell(verifier_bin);
    // let cell_deps
}
