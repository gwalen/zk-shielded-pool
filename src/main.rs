use crate::circuit::constraint_1::project_simple_poseidon_old::run_constraint_1_test_ok;

pub mod circuit;
pub mod imt;

fn main() {
    let _ = run_constraint_1_test_ok();
}
