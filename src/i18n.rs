use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::fs;
use std::sync::{Mutex, RwLock};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum I18nError {
    #[error("Translation key not found: {key}")]
    KeyNotFound { key: String },
    #[error("Invalid locale: {locale}")]
    InvalidLocale { locale: String },
    #[error("Missing translation for key: {key} in locale: {locale}")]
    MissingTranslation { key: String, locale: String },
    #[error("Failed to load translation file: {source}")]
    LoadError { source: std::io::Error },
    #[error("Failed to parse translation file: {source}")]
    ParseError { source: toml::de::Error },
}

type TranslationMap = HashMap<String, String>;
type LocaleData = HashMap<String, TranslationMap>;
type AllTranslations = HashMap<String, LocaleData>;

thread_local! {
    static CURRENT_LOCALE: std::cell::RefCell<String> = std::cell::RefCell::new("en".to_string());
}

static TRANSLATIONS: Lazy<RwLock<AllTranslations>> = Lazy::new(|| RwLock::new(HashMap::new()));

static TEST_MUTEX: Mutex<()> = Mutex::new(());

#[cfg(test)]
fn with_test_mutex<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let _guard = TEST_MUTEX.lock().unwrap();
    f()
}

#[cfg(not(test))]
fn with_test_mutex<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

fn find_locale_path() -> Option<std::path::PathBuf> {
    let possible_paths = vec![
        std::path::PathBuf::from("locales"),
        std::path::PathBuf::from("../locales"),
    ];

    if let Ok(cwd) = std::env::current_dir() {
        possible_paths
            .iter()
            .chain(std::iter::once(&cwd.join("locales")))
            .find(|path| path.exists() && path.is_dir())
            .cloned()
    } else {
        possible_paths
            .into_iter()
            .find(|path| path.exists() && path.is_dir())
    }
}

fn load_locale_file(locale: &str) -> Result<(), I18nError> {
    let locale_path = find_locale_path().ok_or_else(|| I18nError::LoadError {
        source: std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Locales directory not found".to_string(),
        ),
    })?;

    let path = locale_path.join(format!("{}.toml", locale));
    if !path.exists() {
        return Err(I18nError::LoadError {
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("File not found: {:?}", path),
            ),
        });
    }

    let content = fs::read_to_string(&path).map_err(|e| I18nError::LoadError { source: e })?;

    let toml_value: toml::Value =
        toml::from_str(&content).map_err(|e| I18nError::ParseError { source: e })?;

    let mut locale_data = HashMap::<String, HashMap<String, String>>::new();

    if let toml::Value::Table(table) = toml_value {
        for (section, value) in table {
            if let toml::Value::Table(fields) = value {
                let mut section_map = HashMap::<String, String>::new();
                for (key, val) in fields {
                    let s = match val {
                        toml::Value::String(s) => s,
                        toml::Value::Integer(i) => i.to_string(),
                        toml::Value::Float(f) => f.to_string(),
                        toml::Value::Boolean(b) => b.to_string(),
                        _ => continue,
                    };
                    section_map.insert(key, s);
                }
                locale_data.insert(section, section_map);
            }
        }
    }

    let mut translations_guard = TRANSLATIONS.write().unwrap();
    translations_guard.insert(locale.to_string(), locale_data);

    Ok(())
}

fn ensure_locale_loaded(locale: &str) {
    let translations = TRANSLATIONS.read().unwrap();
    if !translations.contains_key(locale) {
        drop(translations);
        let _ = load_locale_file(locale);
    }
}

pub fn set_locale(locale: &str) {
    with_test_mutex(|| {
        let locale_to_set = if ["en", "zh"].contains(&locale) {
            locale.to_string()
        } else {
            "en".to_string()
        };

        ensure_locale_loaded(&locale_to_set);

        CURRENT_LOCALE.with(|cell| {
            *cell.borrow_mut() = locale_to_set;
        });
    })
}

pub fn get_locale() -> String {
    CURRENT_LOCALE.with(|cell| cell.borrow().clone())
}

pub fn translate(key: &str) -> String {
    let locale = get_locale();
    translate_with_locale(key, &locale).unwrap_or_else(|_| format!("[{}]", key))
}

pub fn translate_with_locale(key: &str, locale: &str) -> Result<String, I18nError> {
    with_test_mutex(|| {
        ensure_locale_loaded(locale);

        let translations = TRANSLATIONS.read().unwrap();
        let locale_data = translations
            .get(locale)
            .ok_or_else(|| I18nError::InvalidLocale {
                locale: locale.to_string(),
            })?;

        let parts: Vec<&str> = key.split('.').collect();

        if parts.len() == 2 {
            let section = parts[0];
            let field = parts[1];
            if let Some(section_map) = locale_data.get(section) {
                if let Some(translation) = section_map.get(field) {
                    return Ok(translation.clone());
                }
            }
        }

        Err(I18nError::KeyNotFound {
            key: key.to_string(),
        })
    })
}

pub fn translate_with_args(key: &str, args: &[(&str, &str)]) -> String {
    let locale = get_locale();
    let result = translate_with_locale(key, &locale);
    match result {
        Ok(mut translation) => {
            for &(name, value) in args {
                translation = translation.replace(&format!("{{{}}}", name), value);
            }
            translation
        }
        Err(_) => format!("[{}]", key),
    }
}

pub fn translate_safe(key: &str) -> Result<String, I18nError> {
    let locale = get_locale();
    let translation = translate_with_locale(key, &locale)?;
    if translation.starts_with("[") && translation.ends_with("]") {
        Err(I18nError::MissingTranslation {
            key: key.to_string(),
            locale,
        })
    } else {
        Ok(translation)
    }
}

pub fn is_locale_supported(locale: &str) -> bool {
    ["en", "zh"].contains(&locale)
}

pub fn get_supported_locales() -> Vec<&'static str> {
    vec!["en", "zh"]
}

#[allow(dead_code)]
pub fn preload_all_locales() {
    for &locale in get_supported_locales().iter() {
        ensure_locale_loaded(locale);
    }
}

pub fn reset_for_testing() {
    let _guard = TEST_MUTEX.lock().unwrap();

    CURRENT_LOCALE.with(|cell| {
        *cell.borrow_mut() = "en".to_string();
    });

    let mut translations = TRANSLATIONS.write().unwrap();
    translations.clear();

    drop(translations);
    for &locale in get_supported_locales().iter() {
        let _ = load_locale_file(locale);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_locale() {
        set_locale("en");
        assert_eq!(get_locale(), "en");
        set_locale("zh");
        assert_eq!(get_locale(), "zh");
    }

    #[test]
    fn test_set_invalid_locale_falls_back_to_en() {
        set_locale("invalid");
        assert_eq!(get_locale(), "en");
    }

    #[test]
    fn test_is_locale_supported() {
        assert!(is_locale_supported("en"));
        assert!(is_locale_supported("zh"));
        assert!(!is_locale_supported("ja"));
        assert!(!is_locale_supported("fr"));
    }

    #[test]
    fn test_get_supported_locales() {
        let locales = get_supported_locales();
        assert_eq!(locales.len(), 2);
        assert!(locales.contains(&"en"));
        assert!(locales.contains(&"zh"));
    }

    #[test]
    fn test_translate_returns_string() {
        set_locale("en");
        let result = translate("greeting.hello");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_translate_with_missing_key() {
        set_locale("en");
        let result = translate("nonexistent.key");
        assert!(result.contains("[nonexistent.key]"));
    }
}
