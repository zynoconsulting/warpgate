use serde::{Deserialize, Serialize};

/// API access enabled on a user token, in addition to the user's own permissions.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct ApiTokenPermissions {
    pub user_api: bool,
    pub admin_api: bool,
}

impl Default for ApiTokenPermissions {
    fn default() -> Self {
        Self {
            user_api: true,
            admin_api: true,
        }
    }
}
