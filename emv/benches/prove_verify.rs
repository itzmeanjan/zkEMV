use std::time::Duration;

use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use emv::{Scheme, prepare};

#[path = "../tests/common/mod.rs"]
mod common;

fn prove_verify(c: &mut Criterion) {
    for scheme in [Scheme::VisaFastDda, Scheme::MastercardDda] {
        let (pk, vk) = prepare(&common::compiled(scheme)).unwrap();
        let (statement, card) = common::tap(scheme);

        let proof = pk.prove(&statement, &card).unwrap();
        vk.verify(&statement, &proof).unwrap();

        println!(
            "{}: proof is {:.1} KiB",
            common::package(scheme),
            proof.to_bytes().unwrap().len() as f64 / 1024.0
        );

        let mut group = c.benchmark_group(common::package(scheme));
        group.sample_size(10).sampling_mode(SamplingMode::Flat);

        group.measurement_time(Duration::from_secs(20));
        group.bench_function("prove", |b| b.iter(|| pk.prove(&statement, &card).unwrap()));

        group.measurement_time(Duration::from_secs(5));
        group.bench_function("verify", |b| {
            b.iter(|| vk.verify(&statement, &proof).unwrap())
        });

        group.finish();
    }
}

criterion_group!(benches, prove_verify);
criterion_main!(benches);
