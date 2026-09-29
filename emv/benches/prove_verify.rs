use std::time::Duration;

use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use emv::{Scheme, prepare};

#[path = "../tests/common/mod.rs"]
mod common;

fn prove_verify(c: &mut Criterion) {
    for scheme in [Scheme::VisaFdda, Scheme::MastercardDda] {
        let (pk, vk) = prepare(&common::compiled(scheme)).unwrap();
        let issued = common::issue(scheme, common::today());
        let received = common::receive(&issued);
        let (ca, card) = common::tap(&received);

        let proof = pk.prove(&received, &ca, &card).unwrap();
        vk.verify(issued, &ca, &proof).unwrap();

        println!(
            "{}: proof is {:.1} KiB",
            common::package(scheme),
            f64::from(u32::try_from(proof.to_bytes().unwrap().len()).unwrap()) / 1024.0
        );

        let mut group = c.benchmark_group(common::package(scheme));
        group.sample_size(10).sampling_mode(SamplingMode::Flat);

        group.measurement_time(Duration::from_secs(20));
        group.bench_function("prove", |b| b.iter(|| pk.prove(&received, &ca, &card).unwrap()));

        // Verifying consumes the issued challenge, so each iteration proves a fresh one
        // first, untimed; the short times keep that setup to a few dozen proofs.
        group.warm_up_time(Duration::from_millis(100));
        group.measurement_time(Duration::from_secs(1));
        group.bench_function("verify", |b| {
            b.iter_batched(
                || {
                    let issued = common::issue(scheme, common::today());
                    let received = common::receive(&issued);
                    let (ca, card) = common::tap(&received);
                    let proof = pk.prove(&received, &ca, &card).unwrap();
                    (issued, ca, proof)
                },
                |(issued, ca, proof)| vk.verify(issued, &ca, &proof).unwrap(),
                BatchSize::PerIteration,
            );
        });

        group.finish();
    }
}

criterion_group!(benches, prove_verify);
criterion_main!(benches);
