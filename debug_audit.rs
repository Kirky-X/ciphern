use ciphern::audit::AuditLogger;
use ciphern::Algorithm;

fn main() {
    println!("Testing audit logger...");
    
    // Clear logs
    AuditLogger::clear_logs();
    
    let test_key = "debug_test_key";
    
    // Log some operations
    AuditLogger::log(
        "KEY_GENERATE",
        Some(Algorithm::AES256GCM),
        Some(test_key),
        Ok(()),
    );
    
    // Get logs immediately
    let logs = AuditLogger::get_logs();
    println!("Found {} logs", logs.len());
    
    for (i, log) in logs.iter().enumerate() {
        println!("Log {}: {}", i, log);
        if log.contains("KEY_GENERATE") && log.contains(test_key) {
            println!("FOUND KEY_GENERATE log!");
        }
    }
    
    // Filter logs
    let keygen_logs: Vec<_> = logs
        .iter()
        .filter(|log| log.contains("KEY_GENERATE") && log.contains(test_key))
        .collect();
    
    println!("Found {} KEY_GENERATE logs", keygen_logs.len());
}