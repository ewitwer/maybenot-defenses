# maybenot-defenses

This repository contains code from the following papers:
 - Tobias Pulls and Ethan Witwer. "Maybenot: A Framework for Traffic Analysis Defenses" (https://doi.org/10.1145/3603216.3624953)
 - Ethan Witwer. "State Machine Frameworks for Website Fingerprinting Defenses: Maybe Not" (https://arxiv.org/abs/2310.10789)

## Defenses

Three defenses implementations are provided, which are described in the papers. They are:
 - FRONT [1] (`src/bin/{maybenot-front.rs, pipelined-front.rs}`)
 - RegulaTor [2] (`src/bin/maybenot-regulator.rs`)
 - Surakav [3] (`src/bin/maybenot-surakav.rs`)

**We do not recommend the use of these implementations for protection against website fingerprinting attacks. They are provided only for research purposes.**

## Code Usage

The `maybenot` crate is expected to be in the parent directory. To change this, edit `Cargo.toml`.

Compilation with `cargo build --release` will produce four binaries in `target/release`, one for each defense implementation. They generate machines based on supplied parameters.

Specifically, the binaries can be run as follows:
 - Maybenot FRONT: `./target/release/maybenot-front <Wmax> <N> <num states>`
 - Pipelined FRONT: `./target/release/pipelined-front <Wmax> <N> <num pipelines> <num states>`
 - Maybenot RegulaTor: `./target/release/maybenot-regulator <R> <D> <T> <U> <cells per state>`
 - Maybenot Surakav: `./target/release/maybenot-surakav <ref trace path>`

## License Info

The code in this repository is available under the BSD-3-Clause license.

## References
 [1] Jiajun Gong and Tao Wang, "Zero-delay Lightweight Defenses against Website Fingerprinting" (https://www.usenix.org/conference/usenixsecurity20/presentation/gong)  
 [2] James Holland and Nicholas Hopper, "RegulaTor: A Straightforward Website Fingerprinting Defense" (https://petsymposium.org/popets/2022/popets-2022-0049.php)  
 [3] Jiajun Gong et al., "Surakav: Generating Realistic Traces for a Strong Website Fingerprinting Defense" (https://jiajungong.github.io/files/sp22-surakav.pdf)  
