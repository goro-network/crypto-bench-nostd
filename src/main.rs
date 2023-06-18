use aes_gcm::{AeadInPlace, KeyInit};
use digest::Digest;
use generic_array::typenum::U32;
use rand::RngCore;
use serde::Serialize;

const ITER_COUNT: usize = 1_024;
const NONCE_SIZE_MORUS: usize = 16; // 128-bit
const NONCE_SIZE_AES: usize = 12; // 96-bit
const TAG_SIZE: usize = 16; // 128-bit
const KEY_SIZE: usize = 16; // 128-bit
const HASH_KEY_SIZE: usize = 32; // 256-bit
const HASH_SIZE: usize = 32; // 256-bit

type HeaplessHashKey = [u8; HASH_KEY_SIZE];
type HeaplessKey = [u8; KEY_SIZE];
type HeaplessTag = [u8; TAG_SIZE];
type HeaplessNonceMorus = [u8; NONCE_SIZE_MORUS];
type HeaplessNonceAesGcm = [u8; NONCE_SIZE_AES];
type HeaplessChunk<const CHUNK_SIZE: usize> = [u8; CHUNK_SIZE];
type EncryptFunc<const CHUNK_SIZE: usize, const NONCE_SIZE: usize> =
    fn(
        &HeaplessChunk<CHUNK_SIZE>,
        &HeaplessKey,
        &HeaplessChunk<NONCE_SIZE>,
    ) -> (HeaplessTag, HeaplessChunk<CHUNK_SIZE>);
type DecryptFunc<const CHUNK_SIZE: usize, const NONCE_SIZE: usize> =
    fn(
        &HeaplessChunk<CHUNK_SIZE>,
        &HeaplessKey,
        &HeaplessChunk<NONCE_SIZE>,
        &HeaplessTag,
    ) -> HeaplessChunk<CHUNK_SIZE>;

#[derive(Default, Serialize)]
struct BenchRecord {
    #[serde(rename = "Benchmark")]
    name: String,
    #[serde(rename = "4kiB (B/s)")]
    result_4kib: f64,
    #[serde(rename = "8kiB (B/s)")]
    result_8kib: f64,
    #[serde(rename = "16kiB (B/s)")]
    result_16kib: f64,
    #[serde(rename = "32kiB (B/s)")]
    result_32kib: f64,
    #[serde(rename = "64kiB (B/s)")]
    result_64kib: f64,
    #[serde(rename = "128kiB (B/s)")]
    result_128kib: f64,
    #[serde(rename = "256kiB (B/s)")]
    result_256kib: f64,
    #[serde(rename = "512kiB (B/s)")]
    result_512kib: f64,
}

// region: Utils

fn generate_random_buffer<const SIZE: usize>() -> [u8; SIZE] {
    let mut buffer = [0; SIZE];
    let mut randomizer = rand::thread_rng();
    randomizer.fill_bytes(&mut buffer);

    buffer
}

fn write_bench_results<F: AsRef<std::path::Path>>(
    file_name: F,
    rows: &[BenchRecord],
) -> anyhow::Result<()> {
    let mut csv_writer = csv::WriterBuilder::new()
        .double_quote(true)
        .delimiter(b',')
        .has_headers(true)
        .quote_style(csv::QuoteStyle::NonNumeric)
        .from_path(file_name)?;

    for row in rows {
        csv_writer.serialize(row)?;
    }

    csv_writer.flush()?;

    Ok(())
}

// endregion

// region: Hashing

fn hash_blake2b256(data_chunk: &[u8], _: Option<&HeaplessHashKey>) {
    let mut hasher = blake2::Blake2b::<U32>::new();
    hasher.update(data_chunk);
    let hash_result = hasher.finalize();
    let mut result = [0u8; HASH_SIZE];
    result.copy_from_slice(&hash_result[..]);
}

fn hash_blake3(data_chunk: &[u8], hash_key: Option<&HeaplessHashKey>) {
    let mut hasher = if let Some(key) = hash_key {
        blake3::Hasher::new_keyed(key)
    } else {
        blake3::Hasher::new()
    };
    hasher.update(data_chunk);
    let hash_result = hasher.finalize();
    let mut result = [0u8; HASH_SIZE];
    result.copy_from_slice(&hash_result.as_bytes()[..]);
}

fn bench_hash_iter(
    buffer: &[u8],
    key: Option<&HeaplessHashKey>,
    bench_func: fn(&[u8], Option<&HeaplessHashKey>),
) -> f64 {
    let bandwidth = (buffer.len() * ITER_COUNT) as f64;
    let start_instant = std::time::Instant::now();

    for _ in 0..ITER_COUNT {
        bench_func(buffer, key);
    }

    let duration_secs = start_instant.elapsed().as_secs_f64();

    bandwidth / duration_secs
}

fn bench_hash(
    bench_name: &str,
    hash_function: fn(&[u8], Option<&HeaplessHashKey>),
    with_key: bool,
) -> BenchRecord {
    let mut bench_record = BenchRecord {
        name: bench_name.to_string(),
        ..Default::default()
    };
    let hash_key = if with_key {
        Some(generate_random_buffer::<HASH_KEY_SIZE>())
    } else {
        None
    };
    let buffer_4kib = generate_random_buffer::<{ 4 * 1024 }>();
    let buffer_8kib = generate_random_buffer::<{ 8 * 1024 }>();
    let buffer_16kib = generate_random_buffer::<{ 16 * 1024 }>();
    let buffer_32kib = generate_random_buffer::<{ 32 * 1024 }>();
    let buffer_64kib = generate_random_buffer::<{ 64 * 1024 }>();
    let buffer_128kib = generate_random_buffer::<{ 128 * 1024 }>();
    let buffer_256kib = generate_random_buffer::<{ 256 * 1024 }>();
    let buffer_512kib = generate_random_buffer::<{ 512 * 1024 }>();

    bench_record.result_4kib = bench_hash_iter(&buffer_4kib, hash_key.as_ref(), hash_function);
    bench_record.result_8kib = bench_hash_iter(&buffer_8kib, hash_key.as_ref(), hash_function);
    bench_record.result_16kib = bench_hash_iter(&buffer_16kib, hash_key.as_ref(), hash_function);
    bench_record.result_32kib = bench_hash_iter(&buffer_32kib, hash_key.as_ref(), hash_function);
    bench_record.result_64kib = bench_hash_iter(&buffer_64kib, hash_key.as_ref(), hash_function);
    bench_record.result_128kib = bench_hash_iter(&buffer_128kib, hash_key.as_ref(), hash_function);
    bench_record.result_256kib = bench_hash_iter(&buffer_256kib, hash_key.as_ref(), hash_function);
    bench_record.result_512kib = bench_hash_iter(&buffer_512kib, hash_key.as_ref(), hash_function);

    bench_record
}

// endregion

// region: Encrypt/Decrypt

fn encrypt_morus<const CHUNK_SIZE: usize>(
    plain_chunk: &HeaplessChunk<CHUNK_SIZE>,
    key: &HeaplessKey,
    nonce: &HeaplessNonceMorus,
) -> (HeaplessTag, HeaplessChunk<CHUNK_SIZE>) {
    let mut result = [0; CHUNK_SIZE];
    let encryptor = morus::Morus::new(nonce, key);
    result.copy_from_slice(&plain_chunk[..]);
    let tag = encryptor.encrypt_in_place(&mut result, &[]);

    (tag, result)
}

fn decrypt_morus<const CHUNK_SIZE: usize>(
    encrypted_chunk: &HeaplessChunk<CHUNK_SIZE>,
    key: &HeaplessKey,
    nonce: &HeaplessNonceMorus,
    tag: &HeaplessTag,
) -> HeaplessChunk<CHUNK_SIZE> {
    let mut result = [0; CHUNK_SIZE];
    let decryptor = morus::Morus::new(nonce, key);
    result.copy_from_slice(&encrypted_chunk[..]);
    decryptor.decrypt_in_place(&mut result, tag, &[]).unwrap();

    result
}

fn encrypt_aes_gcm<const CHUNK_SIZE: usize>(
    plain_chunk: &HeaplessChunk<CHUNK_SIZE>,
    key: &HeaplessKey,
    nonce: &HeaplessNonceAesGcm,
) -> (HeaplessTag, HeaplessChunk<CHUNK_SIZE>) {
    let mut result = [0; CHUNK_SIZE];
    let mut tag = [0; TAG_SIZE];
    let encryptor = aes_gcm::Aes128Gcm::new(key.into());
    result.copy_from_slice(&plain_chunk[..]);
    let tag_generic = encryptor
        .encrypt_in_place_detached(nonce.into(), &[], &mut result)
        .unwrap();
    tag.copy_from_slice(&tag_generic[..]);

    (tag, result)
}

fn decrypt_aes_gcm<const CHUNK_SIZE: usize>(
    encrypted_chunk: &HeaplessChunk<CHUNK_SIZE>,
    key: &HeaplessKey,
    nonce: &HeaplessNonceAesGcm,
    tag: &HeaplessTag,
) -> HeaplessChunk<CHUNK_SIZE> {
    let mut result = [0; CHUNK_SIZE];
    let decryptor = aes_gcm::Aes128Gcm::new(key.into());
    result.copy_from_slice(&encrypted_chunk[..]);
    decryptor
        .decrypt_in_place_detached(nonce.into(), &[], &mut result, tag.into())
        .unwrap();

    result
}

fn bench_encrypt_decrypt_iter<const CHUNK_SIZE: usize, const NONCE_SIZE: usize>(
    buffer: &HeaplessChunk<CHUNK_SIZE>,
    key: &HeaplessKey,
    nonce: &HeaplessChunk<NONCE_SIZE>,
    encrypt_func: EncryptFunc<CHUNK_SIZE, NONCE_SIZE>,
    decrypt_func: DecryptFunc<CHUNK_SIZE, NONCE_SIZE>,
) -> f64 {
    let bandwidth = (buffer.len() * ITER_COUNT) as f64;
    let start_instant = std::time::Instant::now();
    let mut decrypted_buffer = [0u8; CHUNK_SIZE];

    for _ in 0..ITER_COUNT {
        let (tag, encrypted_buffer) = encrypt_func(buffer, key, nonce);
        decrypted_buffer = decrypt_func(&encrypted_buffer, key, nonce, &tag);
    }

    assert_eq!(&buffer[..], &decrypted_buffer[..]);
    let duration_secs = start_instant.elapsed().as_secs_f64();

    bandwidth / duration_secs
}

fn bench_morus(bench_name: &str) -> BenchRecord {
    let mut bench_record = BenchRecord {
        name: bench_name.to_string(),
        ..Default::default()
    };
    let nonce = generate_random_buffer::<NONCE_SIZE_MORUS>();
    let key = generate_random_buffer::<KEY_SIZE>();

    bench_record.result_4kib = {
        const SIZE: usize = 4 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_morus::<SIZE>,
            decrypt_morus::<SIZE>,
        )
    };
    bench_record.result_8kib = {
        const SIZE: usize = 8 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_morus::<SIZE>,
            decrypt_morus::<SIZE>,
        )
    };
    bench_record.result_16kib = {
        const SIZE: usize = 16 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_morus::<SIZE>,
            decrypt_morus::<SIZE>,
        )
    };
    bench_record.result_32kib = {
        const SIZE: usize = 32 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_morus::<SIZE>,
            decrypt_morus::<SIZE>,
        )
    };
    bench_record.result_64kib = {
        const SIZE: usize = 64 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_morus::<SIZE>,
            decrypt_morus::<SIZE>,
        )
    };
    bench_record.result_128kib = {
        const SIZE: usize = 128 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_morus::<SIZE>,
            decrypt_morus::<SIZE>,
        )
    };
    bench_record.result_256kib = {
        const SIZE: usize = 256 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_morus::<SIZE>,
            decrypt_morus::<SIZE>,
        )
    };
    bench_record.result_512kib = {
        const SIZE: usize = 512 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_morus::<SIZE>,
            decrypt_morus::<SIZE>,
        )
    };

    bench_record
}

fn bench_aes_gcm(bench_name: &str) -> BenchRecord {
    let mut bench_record = BenchRecord {
        name: bench_name.to_string(),
        ..Default::default()
    };
    let nonce = generate_random_buffer::<NONCE_SIZE_AES>();
    let key = generate_random_buffer::<KEY_SIZE>();

    bench_record.result_4kib = {
        const SIZE: usize = 4 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_aes_gcm::<SIZE>,
            decrypt_aes_gcm::<SIZE>,
        )
    };
    bench_record.result_8kib = {
        const SIZE: usize = 8 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_aes_gcm::<SIZE>,
            decrypt_aes_gcm::<SIZE>,
        )
    };
    bench_record.result_16kib = {
        const SIZE: usize = 16 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_aes_gcm::<SIZE>,
            decrypt_aes_gcm::<SIZE>,
        )
    };
    bench_record.result_32kib = {
        const SIZE: usize = 32 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_aes_gcm::<SIZE>,
            decrypt_aes_gcm::<SIZE>,
        )
    };
    bench_record.result_64kib = {
        const SIZE: usize = 64 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_aes_gcm::<SIZE>,
            decrypt_aes_gcm::<SIZE>,
        )
    };
    bench_record.result_128kib = {
        const SIZE: usize = 128 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_aes_gcm::<SIZE>,
            decrypt_aes_gcm::<SIZE>,
        )
    };
    bench_record.result_256kib = {
        const SIZE: usize = 256 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_aes_gcm::<SIZE>,
            decrypt_aes_gcm::<SIZE>,
        )
    };
    bench_record.result_512kib = {
        const SIZE: usize = 512 * 1024;
        let buffer = generate_random_buffer::<SIZE>();

        bench_encrypt_decrypt_iter(
            &buffer,
            &key,
            &nonce,
            encrypt_aes_gcm::<SIZE>,
            decrypt_aes_gcm::<SIZE>,
        )
    };

    bench_record
}

// endregion

fn main() -> anyhow::Result<()> {
    let results = vec![
        bench_hash("Hashing: Blake2b-256", hash_blake2b256, false),
        bench_hash("Hashing: Blake3", hash_blake3, false),
        bench_hash("Hashing: Blake3 (Salted)", hash_blake3, true),
        bench_morus("Encryption: MORUS-1280-128"),
        bench_aes_gcm("Encryption: AES-GCM-128"),
    ];
    write_bench_results("bench_result.csv", &results)?;

    Ok(())
}
