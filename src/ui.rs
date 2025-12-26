use crate::service::TranslationService;

#[derive(Debug, Clone, PartialEq)]
pub struct UIElement {
    pub key: String,
    pub text: String,
}

impl UIElement {
    pub fn new(key: &str) -> Self {
        let service = TranslationService::new();
        let text = service.t(key);
        Self {
            key: key.to_string(),
            text,
        }
    }

    pub fn refresh(&mut self) {
        let service = TranslationService::new();
        self.text = service.t(&self.key);
    }

    pub fn with_service(key: &str, service: &TranslationService) -> Self {
        let text = service.t(key);
        Self {
            key: key.to_string(),
            text,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalizedMessage {
    pub key: String,
    pub text: String,
    pub args: Vec<(String, String)>,
}

impl LocalizedMessage {
    pub fn new(key: &str) -> Self {
        let service = TranslationService::new();
        let text = service.t(key);
        Self {
            key: key.to_string(),
            text,
            args: Vec::new(),
        }
    }

    pub fn with_args(key: &str, args: &[(&str, &str)]) -> Self {
        let service = TranslationService::new();
        let text = service.t_with_args(key, args);
        let args_converted: Vec<(String, String)> = args
            .iter()
            .map(|&(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Self {
            key: key.to_string(),
            text,
            args: args_converted,
        }
    }

    pub fn refresh(&mut self) {
        let service = TranslationService::new();
        if self.args.is_empty() {
            self.text = service.t(&self.key);
        } else {
            let args_ref: Vec<(&str, &str)> = self
                .args
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            self.text = service.t_with_args(&self.key, &args_ref);
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Button {
    pub key: String,
    pub text: String,
    pub enabled: bool,
}

impl Button {
    pub fn new(key: &str) -> Self {
        let service = TranslationService::new();
        let text = service.t(key);
        Self {
            key: key.to_string(),
            text,
            enabled: true,
        }
    }

    pub fn disabled(key: &str) -> Self {
        let service = TranslationService::new();
        let text = service.t(key);
        Self {
            key: key.to_string(),
            text,
            enabled: false,
        }
    }

    pub fn refresh(&mut self) {
        let service = TranslationService::new();
        self.text = service.t(&self.key);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FormField {
    pub key: String,
    pub label: String,
    pub placeholder: String,
    pub value: String,
}

impl FormField {
    pub fn new(key: &str, placeholder_key: &str) -> Self {
        let service = TranslationService::new();
        let label = service.t(key);
        let placeholder = service.t(placeholder_key);
        Self {
            key: key.to_string(),
            label,
            placeholder,
            value: String::new(),
        }
    }

    pub fn with_value(key: &str, placeholder_key: &str, value: &str) -> Self {
        let service = TranslationService::new();
        let label = service.t(key);
        let placeholder = service.t(placeholder_key);
        Self {
            key: key.to_string(),
            label,
            placeholder,
            value: value.to_string(),
        }
    }

    pub fn refresh(&mut self) {
        let service = TranslationService::new();
        self.label = service.t(&self.key);
        let placeholder_key = format!("{}_placeholder", self.key);
        self.placeholder = service.t(&placeholder_key);
    }

    pub fn set_value(&mut self, value: &str) {
        self.value = value.to_string();
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Label {
    pub key: String,
    pub text: String,
}

impl Label {
    pub fn new(key: &str) -> Self {
        let service = TranslationService::new();
        let text = service.t(key);
        Self {
            key: key.to_string(),
            text,
        }
    }

    pub fn refresh(&mut self) {
        let service = TranslationService::new();
        self.text = service.t(&self.key);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MenuItem {
    pub key: String,
    pub text: String,
    pub shortcut: Option<String>,
    pub children: Vec<MenuItem>,
}

impl MenuItem {
    pub fn new(key: &str) -> Self {
        let service = TranslationService::new();
        let text = service.t(key);
        Self {
            key: key.to_string(),
            text,
            shortcut: None,
            children: Vec::new(),
        }
    }

    pub fn with_shortcut(key: &str, shortcut: &str) -> Self {
        let service = TranslationService::new();
        let text = service.t(key);
        Self {
            key: key.to_string(),
            text,
            shortcut: Some(shortcut.to_string()),
            children: Vec::new(),
        }
    }

    pub fn add_child(&mut self, child: MenuItem) {
        self.children.push(child);
    }

    pub fn refresh(&mut self) {
        let service = TranslationService::new();
        self.text = service.t(&self.key);
        for child in &mut self.children {
            child.refresh();
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    pub key: String,
    pub title: String,
    pub message: String,
    pub level: NotificationLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationLevel {
    Info,
    Warning,
    Error,
    Success,
}

impl Notification {
    pub fn new(key: &str, message_key: &str, level: NotificationLevel) -> Self {
        let service = TranslationService::new();
        let title = service.t(key);
        let message = service.t(message_key);
        Self {
            key: key.to_string(),
            title,
            message,
            level,
        }
    }

    pub fn refresh(&mut self) {
        let service = TranslationService::new();
        self.title = service.t(&self.key);
        let message_key = format!("{}_message", self.key);
        self.message = service.t(&message_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n;

    #[test]
    fn test_ui_element_new() {
        i18n::set_locale("en");
        let element = UIElement::new("common.ok");
        assert_eq!(element.key, "common.ok");
        assert!(!element.text.is_empty());
    }

    #[test]
    fn test_ui_element_refresh() {
        i18n::set_locale("en");
        let mut element = UIElement::new("common.cancel");
        let original_text = element.text.clone();
        i18n::set_locale("zh");
        element.refresh();
        assert_ne!(original_text, element.text);
    }

    #[test]
    fn test_button_new() {
        i18n::set_locale("en");
        let button = Button::new("common.save");
        assert_eq!(button.key, "common.save");
        assert!(button.enabled);
    }

    #[test]
    fn test_button_disabled() {
        i18n::set_locale("en");
        let button = Button::disabled("common.delete");
        assert!(!button.enabled);
    }

    #[test]
    fn test_form_field_new() {
        i18n::set_locale("en");
        let field = FormField::new("user.name", "user.name_placeholder");
        assert!(!field.label.is_empty());
        assert!(!field.placeholder.is_empty());
    }

    #[test]
    fn test_label_new() {
        i18n::set_locale("en");
        let label = Label::new("greeting.welcome");
        assert!(!label.text.is_empty());
    }

    #[test]
    fn test_notification_new() {
        i18n::set_locale("en");
        let notification = Notification::new(
            "error.not_found",
            "error.not_found_message",
            NotificationLevel::Error,
        );
        assert!(!notification.title.is_empty());
        assert!(!notification.message.is_empty());
    }
}
