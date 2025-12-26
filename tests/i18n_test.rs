use ciphern::{
    get_locale, get_supported_locales, is_locale_supported, reset_for_testing, set_locale,
    translate, translate_safe, translate_with_args,
};

fn setup() {
    reset_for_testing();
}

#[test]
fn test_english_translations() {
    setup();
    set_locale("en");
    assert_eq!(translate("greeting.hello"), "Hello, World!");
    assert_eq!(translate("common.ok"), "OK");
    assert_eq!(translate("common.cancel"), "Cancel");
    assert_eq!(translate("common.save"), "Save");
    assert_eq!(translate("error.not_found"), "Not Found");
}

#[test]
fn test_chinese_translations() {
    setup();
    set_locale("zh");
    assert_eq!(translate("greeting.hello"), "你好，世界！");
    assert_eq!(translate("common.ok"), "确定");
    assert_eq!(translate("common.cancel"), "取消");
    assert_eq!(translate("common.save"), "保存");
    assert_eq!(translate("error.not_found"), "未找到");
}

#[test]
fn test_translate_with_args() {
    setup();
    set_locale("en");
    let result = translate_with_args("user.welcome_user", &[("name", "John")]);
    assert_eq!(result, "Welcome, John!");

    set_locale("zh");
    let result = translate_with_args("user.welcome_user", &[("name", "张三")]);
    assert_eq!(result, "欢迎您，张三！");
}

#[test]
fn test_translate_safe_success() {
    setup();
    set_locale("en");
    let result = translate_safe("greeting.hello");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "Hello, World!");
}

#[test]
fn test_translate_safe_missing_key() {
    setup();
    set_locale("en");
    let result = translate_safe("nonexistent.key");
    assert!(result.is_err());
}

#[test]
fn test_locale_persistence() {
    setup();
    set_locale("zh");
    assert_eq!(get_locale(), "zh");
    assert_eq!(translate("greeting.welcome"), "欢迎使用我们的应用程序");

    set_locale("en");
    assert_eq!(get_locale(), "en");
    assert_eq!(translate("greeting.welcome"), "Welcome to our application");
}

#[test]
fn test_invalid_locale_fallback() {
    setup();
    set_locale("fr");
    assert_eq!(get_locale(), "en");
    set_locale("de");
    assert_eq!(get_locale(), "en");
    set_locale("ja");
    assert_eq!(get_locale(), "en");
}

#[test]
fn test_all_locales_supported() {
    assert!(is_locale_supported("en"));
    assert!(is_locale_supported("zh"));
    assert!(!is_locale_supported("ja"));
    assert!(!is_locale_supported("fr"));
    assert!(!is_locale_supported("de"));
    assert!(!is_locale_supported("ko"));
}

#[test]
fn test_get_supported_locales() {
    let locales = get_supported_locales();
    assert_eq!(locales.len(), 2);
    assert!(locales.contains(&"en"));
    assert!(locales.contains(&"zh"));
}

#[test]
fn test_comprehensive_translations() {
    setup();
    set_locale("en");
    assert_eq!(translate("menu.file"), "File");
    assert_eq!(translate("button.submit"), "Submit");
    assert_eq!(translate("status.success"), "Success");

    set_locale("zh");
    assert_eq!(translate("menu.file"), "文件");
    assert_eq!(translate("button.submit"), "提交");
    assert_eq!(translate("status.success"), "成功");
}

#[test]
fn test_form_translations() {
    setup();
    set_locale("en");
    assert_eq!(translate("user.name"), "Name");
    assert_eq!(translate("user.email"), "Email");
    assert_eq!(translate("user.password"), "Password");

    set_locale("zh");
    assert_eq!(translate("user.name"), "姓名");
    assert_eq!(translate("user.email"), "电子邮件");
    assert_eq!(translate("user.password"), "密码");
}

#[test]
fn test_missing_key_returns_placeholder() {
    setup();
    set_locale("en");
    let result = translate("totally.invalid.key.that.does.not.exist");
    assert!(result.contains("[totally.invalid.key.that.does.not.exist]"));
}

#[test]
fn test_error_translations_english() {
    setup();
    use ciphern::{get_localized_error, CryptoError};

    set_locale("en");

    let error = CryptoError::InvalidKeySize {
        expected: 32,
        actual: 16,
    };
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "Invalid Key Size");
    assert_eq!(message, "Expected 32 bytes, got 16 bytes");

    let error = CryptoError::InvalidParameter("test parameter".to_string());
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "Invalid Parameter");
    assert_eq!(message, "test parameter");

    let error = CryptoError::EncryptionFailed("AES error".to_string());
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "Encryption Failed");
    assert_eq!(message, "AES error");

    let error = CryptoError::DecryptionFailed("RSA error".to_string());
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "Decryption Failed");
    assert_eq!(message, "RSA error");

    let error = CryptoError::KeyNotFound("master_key".to_string());
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "Key Not Found");
    assert_eq!(message, "master_key");

    let error = CryptoError::UnsupportedAlgorithm("Blowfish".to_string());
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "Unsupported Algorithm");
    assert_eq!(message, "Blowfish");

    let error = CryptoError::InsufficientEntropy;
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "Insufficient Entropy");
    assert_eq!(
        message,
        "The system does not have enough entropy to generate secure random numbers"
    );

    let error = CryptoError::UnknownError;
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "Unknown Error");
    assert_eq!(message, "An unknown error occurred");
}

#[test]
fn test_error_translations_chinese() {
    setup();
    use ciphern::{get_localized_error, CryptoError};

    set_locale("zh");

    let error = CryptoError::InvalidKeySize {
        expected: 32,
        actual: 16,
    };
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "无效的密钥大小");
    assert_eq!(message, "期望 32 字节，实际 16 字节");

    let error = CryptoError::InvalidParameter("测试参数".to_string());
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "无效参数");
    assert_eq!(message, "测试参数");

    let error = CryptoError::EncryptionFailed("AES 错误".to_string());
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "加密失败");
    assert_eq!(message, "AES 错误");

    let error = CryptoError::DecryptionFailed("RSA 错误".to_string());
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "解密失败");
    assert_eq!(message, "RSA 错误");

    let error = CryptoError::KeyNotFound("主密钥".to_string());
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "找不到密钥");
    assert_eq!(message, "主密钥");

    let error = CryptoError::UnsupportedAlgorithm("Blowfish".to_string());
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "不支持的算法");
    assert_eq!(message, "Blowfish");

    let error = CryptoError::InsufficientEntropy;
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "熵不足");
    assert_eq!(message, "系统没有足够的熵来生成安全的随机数");

    let error = CryptoError::UnknownError;
    let (title, message) = get_localized_error(&error);
    assert_eq!(title, "未知错误");
    assert_eq!(message, "发生未知错误");
}

#[test]
fn test_error_with_complex_args() {
    setup();
    use ciphern::CryptoError;

    set_locale("en");

    let error = CryptoError::KeyUsageLimitExceeded {
        key_id: "master-001".to_string(),
        limit_type: "encryption".to_string(),
        current_count: 1000,
        max_count: 10000,
    };
    let message = ciphern::get_localized_message(&error);
    assert!(message.contains("master-001"));
    assert!(message.contains("encryption"));
    assert!(message.contains("1000"));
    assert!(message.contains("10000"));

    set_locale("zh");
    let message = ciphern::get_localized_message(&error);
    assert!(message.contains("master-001"));
    assert!(message.contains("encryption"));
    assert!(message.contains("1000"));
    assert!(message.contains("10000"));
}

#[test]
fn test_error_title_only() {
    setup();
    use ciphern::{get_localized_title, CryptoError};

    set_locale("en");
    let error = CryptoError::IoError(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "file not found",
    ));
    assert_eq!(get_localized_title(&error), "I/O Error");

    set_locale("zh");
    assert_eq!(get_localized_title(&error), "I/O 错误");
}
