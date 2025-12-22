// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

#[cfg(test)]
mod debug_tests {
    #[test]
    fn debug_cache_partition() {
        let partition = CachePartition::new(4, 2);
        let data = partition.allocate_in_partition(256);
        
        println!("Data length: {}", data.len());
        
        // Check that only partition-aligned locations are touched
        let mut touched_count = 0;
        for i in 0..data.len() {
            if data[i] == 0xFF {
                touched_count += 1;
                if touched_count <= 5 { // Only print first few
                    println!("Touched at index: {}", i);
                }
            }
        }
        
        println!("Touched count: {}", touched_count);
        
        // Calculate expected count
        let expected_count = ((256 * 4 * 64) - 2) / (4 * 64) + 1;
        println!("Expected count: {}", expected_count);
        
        // Let's manually calculate what it should be
        // We start at index 2, step by 256 (4*64), until we reach 65536
        // So we touch indices: 2, 258, 514, 770, ...
        // This is an arithmetic sequence: a_n = 2 + (n-1)*256
        // We want the largest n such that a_n < 65536
        // 2 + (n-1)*256 < 65536
        // (n-1)*256 < 65534
        // n-1 < 65534/256 = 256.0
        // n < 257.0
        // So n = 256
        let manual_calc = 256;
        println!("Manual calculation: {}", manual_calc);
        
        assert_eq!(touched_count, manual_calc);
    }
}