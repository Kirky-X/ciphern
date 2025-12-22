// Copyright (c) 2025 Kirky.X
// 
// Licensed under the MIT License
// See LICENSE file in the project root for full license information.

use ciphern::audit::AuditLogger;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[test]
fn test_prometheus_exporter_http_endpoint() {
    let port = 9091;
    AuditLogger::start_exporter(port);

    // 等待服务启动
    std::thread::sleep(Duration::from_millis(500));

    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{}", port)).expect("Failed to connect to exporter");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
    stream.write_all(request.as_bytes()).unwrap();

    // 模拟一些操作以产生指标
    AuditLogger::log_unauthorized_access("TEST", None, None, None, "Test alert");

    let metrics_str = AuditLogger::gather_metrics();
    println!("Directly gathered metrics: {}", metrics_str);

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();

    println!("Response: {}", response);
    assert!(response.contains("HTTP/1.1 200 OK"));
    assert!(response.contains("Content-Type: text/plain"));
    assert!(response.contains("security_alerts_total"));
}
