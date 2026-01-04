//! 权限匹配器
//!
//! 实现权限的解析、匹配和验证逻辑。

/// 权限匹配器
#[derive(Debug, Clone, Default)]
pub struct PermissionMatcher;

impl PermissionMatcher {
    /// 创建新的匹配器
    pub fn new() -> Self {
        Self
    }

    /// 检查权限是否匹配
    ///
    /// 支持三种匹配方式：
    /// 1. 精确匹配: `orders:delete` 匹配 `orders:delete`
    /// 2. 通配符匹配: `orders:*` 匹配 `orders:read`, `orders:write`, `orders:delete`
    /// 3. 全局管理员: `*:*` 匹配任意权限
    ///
    /// # 参数
    /// * `available` - 可用的权限列表
    /// * `required` - 需要的权限（格式: "resource:action"）
    pub fn matches(&self, available: &[String], required: &str) -> bool {
        // 解析需要的权限
        let req_parts: Vec<&str> = required.split(':').collect();
        if req_parts.len() != 2 {
            return false;
        }

        let req_resource = req_parts[0];
        let req_action = req_parts[1];

        for perm in available {
            let perm_parts: Vec<&str> = perm.split(':').collect();
            if perm_parts.len() != 2 {
                continue;
            }

            let perm_resource = perm_parts[0];
            let perm_action = perm_parts[1];

            // 精确匹配
            if perm_resource == req_resource && perm_action == req_action {
                return true;
            }

            // 通配符匹配：resource:* 匹配任意 action
            if perm_resource == req_resource && perm_action == "*" {
                return true;
            }

            // 全局管理员：*:*
            if perm_resource == "*" && perm_action == "*" {
                return true;
            }
        }

        false
    }

    /// 检查是否拥有所有要求的权限
    pub fn has_all_permissions(&self, available: &[String], required: &[String]) -> bool {
        required.iter().all(|req| self.matches(available, req))
    }

    /// 检查是否拥有任意一个要求的权限
    pub fn has_any_permission(&self, available: &[String], required: &[String]) -> bool {
        required.iter().any(|req| self.matches(available, req))
    }

    /// 检查是否需要管理员权限（*:*）
    pub fn requires_admin(&self, required: &[String]) -> bool {
        required.iter().any(|req| {
            let parts: Vec<&str> = req.split(':').collect();
            parts.len() == 2 && parts[0] == "*" && parts[1] == "*"
        })
    }

    /// 合并权限列表（去重）
    pub fn merge_permissions(&self, permissions: &[Vec<String>]) -> Vec<String> {
        let mut merged = Vec::new();
        for perm_list in permissions {
            for perm in perm_list {
                if !merged.contains(perm) {
                    merged.push(perm.clone());
                }
            }
        }
        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let matcher = PermissionMatcher::new();
        let available = vec!["users:read".to_string(), "orders:write".to_string()];

        assert!(matcher.matches(&available, "users:read"));
        assert!(matcher.matches(&available, "orders:write"));
        assert!(!matcher.matches(&available, "users:write"));
        assert!(!matcher.matches(&available, "products:read"));
    }

    #[test]
    fn test_wildcard_match() {
        let matcher = PermissionMatcher::new();
        let available = vec!["orders:*".to_string(), "users:read".to_string()];

        assert!(matcher.matches(&available, "orders:read"));
        assert!(matcher.matches(&available, "orders:write"));
        assert!(matcher.matches(&available, "orders:delete"));
        assert!(!matcher.matches(&available, "products:read"));
    }

    #[test]
    fn test_admin_match() {
        let matcher = PermissionMatcher::new();
        let available = vec!["*:*".to_string(), "users:read".to_string()];

        assert!(matcher.matches(&available, "orders:read"));
        assert!(matcher.matches(&available, "orders:write"));
        assert!(matcher.matches(&available, "products:delete"));
        assert!(matcher.matches(&available, "users:read"));
    }

    #[test]
    fn test_has_all_permissions() {
        let matcher = PermissionMatcher::new();
        let available = vec!["users:read".to_string(), "orders:write".to_string()];

        assert!(matcher.has_all_permissions(&available, &["users:read".to_string()]));
        assert!(matcher.has_all_permissions(&available, &["users:read".to_string(), "orders:write".to_string()]));
        assert!(!matcher.has_all_permissions(&available, &["users:read".to_string(), "orders:delete".to_string()]));
    }

    #[test]
    fn test_has_any_permission() {
        let matcher = PermissionMatcher::new();
        let available = vec!["users:read".to_string()];

        assert!(matcher.has_any_permission(&available, &["users:read".to_string()]));
        assert!(matcher.has_any_permission(&available, &["users:read".to_string(), "orders:write".to_string()]));
        assert!(!matcher.has_any_permission(&available, &["orders:write".to_string(), "products:delete".to_string()]));
    }

    #[test]
    fn test_requires_admin() {
        let matcher = PermissionMatcher::new();

        assert!(matcher.requires_admin(&["*:*".to_string()]));
        assert!(matcher.requires_admin(&["users:read".to_string(), "*:*".to_string()]));
        assert!(!matcher.requires_admin(&["users:read".to_string(), "orders:write".to_string()]));
    }
}
