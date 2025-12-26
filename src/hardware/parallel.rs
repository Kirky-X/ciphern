// Copyright (c) 2025 Kirky.X
//
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use rayon::prelude::*;

#[allow(dead_code)]
pub struct ParallelProcessor;

#[allow(dead_code)]
impl ParallelProcessor {
    #[inline]
    pub fn parallelize_chunks<R, F>(data: &[u8], chunk_size: usize, f: F) -> Vec<R>
    where
        R: Send,
        F: Fn(&[u8]) -> R + Sync + Send,
    {
        let chunks: Vec<&[u8]> = data.chunks(chunk_size).filter(|c| !c.is_empty()).collect();

        if chunks.is_empty() {
            return Vec::new();
        }

        #[allow(clippy::redundant_closure)]
        chunks.par_iter().map(|chunk| f(chunk)).collect() // Explicit closure needed for double reference
    }

    #[inline]
    pub fn parallelize_256_chunks<R, F>(data: &[u8], f: F) -> Vec<R>
    where
        R: Send,
        F: Fn(&[u8]) -> R + Sync + Send,
    {
        Self::parallelize_chunks(data, 256, f)
    }

    #[inline]
    pub fn parallelize_4096_chunks<R, F>(data: &[u8], f: F) -> Vec<R>
    where
        R: Send,
        F: Fn(&[u8]) -> R + Sync + Send,
    {
        Self::parallelize_chunks(data, 4096, f)
    }

    #[inline]
    pub fn parallelize_with_rayon<T, R, F>(items: &[T], f: F) -> Vec<R>
    where
        T: Send + Sync,
        R: Send,
        F: Fn(&T) -> R + Sync + Send,
    {
        #[allow(clippy::redundant_closure)]
        items.par_iter().map(|item| f(item)).collect() // Explicit closure needed for double reference
    }

    #[inline]
    pub fn parallel_map<I, R, F>(items: I, f: F) -> Vec<R>
    where
        I: IntoParallelIterator,
        I::Item: Send,
        R: Send,
        F: Fn(I::Item) -> R + Sync + Send,
    {
        items.into_par_iter().map(f).collect()
    }
}

#[allow(dead_code)]
#[inline]
pub fn parallel_encrypt_chunks(
    data: &[u8],
    encrypt_fn: impl Fn(&[u8]) -> Result<Vec<u8>, crate::CryptoError> + Sync,
) -> Result<Vec<u8>, crate::CryptoError> {
    let results = ParallelProcessor::parallelize_4096_chunks(data, &encrypt_fn);

    let mut combined = Vec::with_capacity(data.len());
    for result in results {
        combined.extend(result?);
    }
    Ok(combined)
}

#[allow(dead_code)]
#[inline]
pub fn parallel_hash_chunks(
    data: &[u8],
    hash_fn: impl Fn(&[u8]) -> Result<Vec<u8>, crate::CryptoError> + Sync,
) -> Result<Vec<u8>, crate::CryptoError> {
    let results = ParallelProcessor::parallelize_4096_chunks(data, &hash_fn);

    let mut combined = Vec::with_capacity(data.len());
    for result in results {
        combined.extend(result?);
    }
    Ok(combined)
}

#[allow(dead_code)]
#[inline]
pub fn parallel_hash_combine(hashes: Vec<Vec<u8>>) -> Vec<u8> {
    let mut combined = Vec::with_capacity(hashes.iter().map(|h| h.len()).sum());
    for hash in hashes {
        combined.extend(hash);
    }
    combined
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_processing() {
        let data = vec![1u8; 4096];
        let result = ParallelProcessor::parallelize_256_chunks(&data, |chunk| chunk.len());
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_parallel_encrypt_chunks() {
        let data = vec![0u8; 8192];
        let result = parallel_encrypt_chunks(&data, |chunk| Ok(chunk.to_vec()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 8192);
    }

    #[test]
    fn test_parallel_map() {
        let items: Vec<i32> = (0..100).collect();
        let doubled: Vec<i32> = ParallelProcessor::parallel_map(items, |x: i32| x * 2);

        // Verify length is preserved
        assert_eq!(doubled.len(), 100);

        // Verify transformation is correct (order-independent checks)
        let mut expected: Vec<i32> = (0..100).map(|x| x * 2).collect();
        let mut doubled_sorted = doubled.clone();
        doubled_sorted.sort();
        expected.sort();
        assert_eq!(doubled_sorted, expected);

        // Additional verification for specific values
        assert!(doubled.contains(&0));
        assert!(doubled.contains(&100));
        assert!(doubled.contains(&198));
    }

    #[test]
    fn test_parallel_hash_combine() {
        let hashes = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];
        let combined = parallel_hash_combine(hashes);
        assert_eq!(combined.len(), 96);
    }
}
