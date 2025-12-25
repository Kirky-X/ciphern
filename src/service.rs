use crate::i18n;

#[derive(Debug)]
pub struct TranslationService {
    pub current_locale: String,
}

impl TranslationService {
    pub fn new() -> Self {
        let locale = i18n::get_locale();
        Self {
            current_locale: locale,
        }
    }

    pub fn set_locale(&mut self, locale: &str) {
        i18n::set_locale(locale);
        self.current_locale = i18n::get_locale();
    }

    pub fn t(&self, key: &str) -> String {
        i18n::translate(key)
    }

    pub fn t_with_args(&self, key: &str, args: &[(&str, &str)]) -> String {
        i18n::translate_with_args(key, args)
    }

    pub fn t_safe(&self, key: &str) -> Result<String, i18n::I18nError> {
        i18n::translate_safe(key)
    }

    pub fn get_locale(&self) -> &str {
        &self.current_locale
    }

    pub fn is_locale_supported(&self, locale: &str) -> bool {
        i18n::is_locale_supported(locale)
    }

    pub fn get_supported_locales(&self) -> Vec<&'static str> {
        i18n::get_supported_locales()
    }
}

impl Default for TranslationService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translation_service_new() {
        let service = TranslationService::new();
        assert!(!service.current_locale.is_empty());
    }

    #[test]
    fn test_translation_service_set_locale() {
        let mut service = TranslationService::new();
        service.set_locale("zh");
        assert_eq!(service.current_locale, "zh");
    }

    #[test]
    fn test_translation_service_t() {
        i18n::set_locale("en");
        let service = TranslationService::new();
        let result = service.t("greeting.hello");
        assert!(!result.is_empty());
    }
}
