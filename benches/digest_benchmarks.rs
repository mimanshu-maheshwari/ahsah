use ahsah::{Digest, Md5, Sha224, Sha256, Sha384, Sha512};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

#[derive(Clone, Copy)]
struct Algorithm {
    name: &'static str,
    one_shot: fn(&[u8]) -> ahsah::DigestBytes,
    incremental: fn(&[u8]) -> ahsah::DigestBytes,
}

const INPUT_SIZES: &[usize] = &[0, 64, 1024, 16 * 1024];
const CHUNK_SIZE: usize = 64;

fn algorithms() -> [Algorithm; 5] {
    [
        Algorithm {
            name: "md5",
            one_shot: Md5::digest,
            incremental: incremental_digest::<Md5>,
        },
        Algorithm {
            name: "sha224",
            one_shot: Sha224::digest,
            incremental: incremental_digest::<Sha224>,
        },
        Algorithm {
            name: "sha256",
            one_shot: Sha256::digest,
            incremental: incremental_digest::<Sha256>,
        },
        Algorithm {
            name: "sha384",
            one_shot: Sha384::digest,
            incremental: incremental_digest::<Sha384>,
        },
        Algorithm {
            name: "sha512",
            one_shot: Sha512::digest,
            incremental: incremental_digest::<Sha512>,
        },
    ]
}

fn incremental_digest<T>(data: &[u8]) -> ahsah::DigestBytes
where
    T: Digest + Default,
{
    let mut digest = T::default();
    for chunk in data.chunks(CHUNK_SIZE) {
        digest.update(chunk);
    }
    digest.finalize()
}

fn benchmark_algorithm(c: &mut Criterion, algorithm: Algorithm) {
    let mut group = c.benchmark_group(algorithm.name);

    for &size in INPUT_SIZES {
        let data = generate_input(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("one-shot", size), &data, |bench, input| {
            bench.iter(|| black_box((algorithm.one_shot)(black_box(input.as_slice()))));
        });

        group.bench_with_input(
            BenchmarkId::new("incremental", size),
            &data,
            |bench, input| {
                bench.iter(|| black_box((algorithm.incremental)(black_box(input.as_slice()))));
            },
        );
    }

    group.finish();
}

fn generate_input(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    for (index, byte) in data.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(31).wrapping_add(7);
    }
    data
}

fn digest_benchmarks(c: &mut Criterion) {
    for algorithm in algorithms() {
        benchmark_algorithm(c, algorithm);
    }
}

criterion_group!(benches, digest_benchmarks);
criterion_main!(benches);
