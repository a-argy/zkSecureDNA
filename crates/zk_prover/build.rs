fn main() {
    // Set SP1_SKIP_PROGRAM_BUILD=true to reuse previously built ELFs.
    for program in ["hash", "checksum", "aggregate"] {
        sp1_build::build_program(&format!("../../zk/programs/{program}"));
    }
}
