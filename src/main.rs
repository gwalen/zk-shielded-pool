use crate::circuit::constraint_1::project_simple_poseidon::run_constraint_1_test_ok;
use crate::circuit::constraint_2::pool_membership::run_constraint_2_pool_membership_test_ok;

pub mod circuit;

fn main() {
    // let _ = run_constraint_1_test_ok();
    let _ = run_constraint_2_pool_membership_test_ok();
}
