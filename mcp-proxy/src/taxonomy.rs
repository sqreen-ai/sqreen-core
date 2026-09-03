//! Normalized security taxonomy for agent actions.
//!
//! Provider tool names (`read_file`, `Bash`, `browser_click`) are *hints*, not semantics.
//! This module maps the structural facts already derived by [`crate::classify`] — tool
//! capability, verb, target resource, destination, credentials, and deployment context —
//! into a small, stable vocabulary that policy can target without knowing MCP from Cursor.
//!
//! # Integration point
//!
//! [`SecurityClassification`] is attached to [`crate::action::AgentAction`] before the
//! gateway evaluates policy. Adapters populate an initial classification from wire data;
//! [`AgentAction::refresh_security_classification`] recomputes it after identity enrichment
//! so flags like `risk.production` reflect the final environment tier.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::action::{
    AgentAction, Arguments, DataCategory, Destination, EnvironmentTier, Operation, Resource,
    Sensitivity, ToolType,
};
use crate::classify::Classification;

/* ------------------------------------------------------------------------ */
/* Vocabulary                                                               */
/* ------------------------------------------------------------------------ */

/// What kind of change the action attempts — independent of provider naming.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ActionCategory {
    Read,
    Write,
    Execute,
    Delete,
    Create,
    Modify,
    Send,
    Query,
    Authenticate,
    Escalate,
    Deploy,
    NetworkRequest,
    #[default]
    Unknown,
}

impl ActionCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
            Self::Delete => "delete",
            Self::Create => "create",
            Self::Modify => "modify",
            Self::Send => "send",
            Self::Query => "query",
            Self::Authenticate => "authenticate",
            Self::Escalate => "escalate",
            Self::Deploy => "deploy",
            Self::NetworkRequest => "network_request",
            Self::Unknown => "unknown",
        }
    }
}

/// What class of resource the action touches — several may apply at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceCategory {
    Filesystem,
    Credential,
    SourceCode,
    Database,
    CloudResource,
    Network,
    Api,
    Email,
    Browser,
    Secret,
    Pii,
    FinancialData,
    ProductionSystem,
    ExternalService,
    Unknown,
}

impl ResourceCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Credential => "credential",
            Self::SourceCode => "source_code",
            Self::Database => "database",
            Self::CloudResource => "cloud_resource",
            Self::Network => "network",
            Self::Api => "api",
            Self::Email => "email",
            Self::Browser => "browser",
            Self::Secret => "secret",
            Self::Pii => "pii",
            Self::FinancialData => "financial_data",
            Self::ProductionSystem => "production_system",
            Self::ExternalService => "external_service",
            Self::Unknown => "unknown",
        }
    }
}

/// Risk-sensitive properties derived from structure, not from the tool name alone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskProfile {
    pub destructive: bool,
    pub external_destination: bool,
    pub privileged: bool,
    pub credential_access: bool,
    pub sensitive_data_access: bool,
    pub production: bool,
    pub irreversible: bool,
    pub bulk_operation: bool,
}

impl RiskProfile {
    pub fn field(&self, name: &str) -> Option<String> {
        match name.trim() {
            "destructive" => Some(self.destructive.to_string()),
            "external_destination" => Some(self.external_destination.to_string()),
            "privileged" => Some(self.privileged.to_string()),
            "credential_access" => Some(self.credential_access.to_string()),
            "sensitive_data_access" => Some(self.sensitive_data_access.to_string()),
            "production" => Some(self.production.to_string()),
            "irreversible" => Some(self.irreversible.to_string()),
            "bulk_operation" => Some(self.bulk_operation.to_string()),
            _ => None,
        }
    }
}

/// Normalized security semantics for one action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityClassification {
    pub action: ActionCategory,
    pub resources: Vec<ResourceCategory>,
    pub risk: RiskProfile,
}

impl Default for SecurityClassification {
    fn default() -> Self {
        Self {
            action: ActionCategory::Unknown,
            resources: Vec::new(),
            risk: RiskProfile::default(),
        }
    }
}

impl SecurityClassification {
    /// Returns `true` when the action touches `category`.
    pub fn touches_resource(&self, category: ResourceCategory) -> bool {
        self.resources.contains(&category)
    }
}

/// Flattened view for declarative policy predicates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxonomyMatchContext<'a> {
    pub action: ActionCategory,
    pub resources: &'a [ResourceCategory],
    pub risk: &'a RiskProfile,
}

impl<'a> TaxonomyMatchContext<'a> {
    pub fn from_action(action: &'a AgentAction) -> Self {
        Self {
            action: action.security.action,
            resources: &action.security.resources,
            risk: &action.security.risk,
        }
    }

    pub fn field(&self, name: &str) -> Option<String> {
        let key = name.trim();
        if key.is_empty() {
            return None;
        }

        if let Some(flag) = key.strip_prefix("risk.") {
            return self.risk.field(flag);
        }

        if let Some(resource) = key.strip_prefix("resource.") {
            let expected = resource.replace('-', "_");
            let matched = self
                .resources
                .iter()
                .any(|category| category.as_str() == expected || category.as_str() == resource);
            return Some(matched.to_string());
        }

        if key == "action" {
            return Some(self.action.as_str().to_string());
        }

        if key.starts_with("action.") {
            let expected = key.strip_prefix("action.")?;
            return Some((self.action.as_str() == expected).to_string());
        }

        None
    }
}

/* ------------------------------------------------------------------------ */
/* Classification engine                                                    */
/* ------------------------------------------------------------------------ */

/// Classifies a fully populated action.
///
/// Re-runs [`crate::classify`] to fill gaps when adapters left descriptive fields at their
/// defaults, so policy tests and bare builders still get argument-shape semantics.
pub fn classify_action(action: &AgentAction) -> SecurityClassification {
    let inferred = crate::classify::classify(&action.tool_name, &action.arguments);
    let structural = merge_structural(action, &inferred);

    classify_structural(
        &structural,
        &action.tool_name,
        &action.arguments,
        action.identity.environment.tier,
    )
}

fn merge_structural(action: &AgentAction, inferred: &Classification) -> Classification {
    let mut data_classification = action.data_classification.clone();
    for category in &inferred.data_classification.categories {
        if !data_classification.categories.contains(category) {
            data_classification.categories.push(*category);
        }
    }
    data_classification.categories.sort();
    data_classification.categories.dedup();
    if inferred.data_classification.sensitivity > data_classification.sensitivity {
        data_classification.sensitivity = inferred.data_classification.sensitivity;
    }

    Classification {
        tool_type: if action.tool_type == ToolType::UNKNOWN {
            inferred.tool_type.clone()
        } else {
            action.tool_type.clone()
        },
        operation: if action.operation == Operation::Invoke {
            inferred.operation
        } else {
            action.operation
        },
        target_resource: action
            .target_resource
            .clone()
            .or_else(|| inferred.target_resource.clone()),
        destination: action
            .destination
            .clone()
            .or_else(|| inferred.destination.clone()),
        data_classification,
        credentials: if action.credentials.is_empty() {
            inferred.credentials.clone()
        } else {
            action.credentials.clone()
        },
        tool_knowledge: inferred.tool_knowledge,
    }
}

/// Classifies from the adapter-stage structural facts plus deployment tier.
pub fn classify_structural(
    structural: &Classification,
    tool_name: &str,
    arguments: &Arguments,
    environment_tier: EnvironmentTier,
) -> SecurityClassification {
    let structural = augment_from_arguments(structural.clone(), arguments);

    let action = derive_action_category(
        &structural.tool_type,
        structural.operation,
        tool_name,
        &structural.target_resource,
        &structural.destination,
        arguments,
    );

    let resources = derive_resource_categories(&structural, tool_name, environment_tier);

    let risk = derive_risk_profile(
        action,
        &resources,
        &structural,
        tool_name,
        arguments,
        environment_tier,
    );

    SecurityClassification {
        action,
        resources,
        risk,
    }
}

fn augment_from_arguments(mut structural: Classification, arguments: &Arguments) -> Classification {
    if structural.tool_type == ToolType::UNKNOWN {
        if database_statement(arguments).is_some() {
            structural.tool_type = ToolType::DATABASE;
            if structural.operation == Operation::Invoke {
                structural.operation = Operation::Query;
            }
        } else if arguments
            .first_string_field(["url", "uri", "endpoint"].iter().copied())
            .is_some()
        {
            structural.tool_type = ToolType::NETWORK;
            if structural.operation == Operation::Invoke {
                structural.operation = Operation::Connect;
            }
        }
    }

    structural
}

fn derive_action_category(
    tool_type: &ToolType,
    operation: Operation,
    tool_name: &str,
    target: &Option<Resource>,
    destination: &Option<Destination>,
    arguments: &Arguments,
) -> ActionCategory {
    if semantic_hint(tool_name, &["deploy", "release", "rollout", "promote"]) {
        return ActionCategory::Deploy;
    }
    if semantic_hint(
        tool_name,
        &["auth", "login", "oauth", "sso", "token_refresh"],
    ) {
        return ActionCategory::Authenticate;
    }
    if semantic_hint(tool_name, &["escalate", "sudo", "privilege", "assume_role"]) {
        return ActionCategory::Escalate;
    }

    if let Some(Resource::Command { raw, .. }) = target {
        if command_implies(category_from_command(raw), ActionCategory::Unknown)
            != ActionCategory::Unknown
        {
            return command_implies(category_from_command(raw), ActionCategory::Unknown);
        }
    }

    if let Some(statement) = database_statement(arguments) {
        if sql_implies_delete(&statement) {
            return ActionCategory::Delete;
        }
        if sql_implies_write(&statement) {
            return ActionCategory::Modify;
        }
        return ActionCategory::Query;
    }

    match tool_type.as_str() {
        "messaging" => ActionCategory::Send,
        "network" | "search" => ActionCategory::NetworkRequest,
        _ => match operation {
            Operation::Delete => ActionCategory::Delete,
            Operation::Query => ActionCategory::Query,
            Operation::Execute => ActionCategory::Execute,
            Operation::Connect => ActionCategory::NetworkRequest,
            Operation::Navigate => ActionCategory::NetworkRequest,
            Operation::Read | Operation::List => ActionCategory::Read,
            Operation::Search => ActionCategory::Read,
            Operation::Write => {
                if create_like(tool_name, arguments) {
                    ActionCategory::Create
                } else {
                    ActionCategory::Modify
                }
            }
            Operation::Invoke if tool_type.as_str() == "filesystem" => {
                if semantic_hint(tool_name, &["delete", "remove", "unlink", "rm"]) {
                    ActionCategory::Delete
                } else if semantic_hint(tool_name, &["write", "edit", "patch", "move", "copy"]) {
                    ActionCategory::Modify
                } else if create_like(tool_name, arguments) {
                    ActionCategory::Create
                } else {
                    ActionCategory::Read
                }
            }
            Operation::Invoke => {
                if destination.is_some() {
                    ActionCategory::NetworkRequest
                } else {
                    ActionCategory::Unknown
                }
            }
        },
    }
}

fn derive_resource_categories(
    structural: &Classification,
    tool_name: &str,
    environment_tier: EnvironmentTier,
) -> Vec<ResourceCategory> {
    let mut set = BTreeSet::new();

    match structural.tool_type.as_str() {
        "filesystem" => {
            set.insert(ResourceCategory::Filesystem);
        }
        "database" => {
            set.insert(ResourceCategory::Database);
        }
        "browser" => {
            set.insert(ResourceCategory::Browser);
        }
        "network" => {
            set.insert(ResourceCategory::Network);
            set.insert(ResourceCategory::Api);
        }
        "messaging" => {
            set.insert(ResourceCategory::Email);
        }
        "shell" => {
            set.insert(ResourceCategory::Filesystem);
        }
        _ => {}
    }

    if !structural.credentials.is_empty() {
        set.insert(ResourceCategory::Credential);
        set.insert(ResourceCategory::Secret);
    }

    for category in &structural.data_classification.categories {
        match category {
            DataCategory::Secret | DataCategory::Credential => {
                set.insert(ResourceCategory::Secret);
                set.insert(ResourceCategory::Credential);
            }
            DataCategory::Pii => {
                set.insert(ResourceCategory::Pii);
            }
            DataCategory::Financial => {
                set.insert(ResourceCategory::FinancialData);
            }
            DataCategory::SourceCode => {
                set.insert(ResourceCategory::SourceCode);
            }
            DataCategory::Infrastructure => {
                set.insert(ResourceCategory::CloudResource);
            }
        }
    }

    if let Some(path) = target_path(&structural.target_resource) {
        classify_path(&mut set, path);
    }

    if let Some(Resource::Database { database, .. }) = &structural.target_resource {
        if database
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case("prod"))
        {
            set.insert(ResourceCategory::ProductionSystem);
        }
    }

    if structural.destination.is_some() {
        set.insert(ResourceCategory::ExternalService);
    }

    if semantic_hint(
        tool_name,
        &["s3", "lambda", "ec2", "gcs", "azure", "k8s", "kubectl"],
    ) {
        set.insert(ResourceCategory::CloudResource);
    }

    if environment_tier == EnvironmentTier::Production {
        set.insert(ResourceCategory::ProductionSystem);
    }

    if set.is_empty() {
        set.insert(ResourceCategory::Unknown);
    }

    set.into_iter().collect()
}

fn derive_risk_profile(
    action: ActionCategory,
    resources: &[ResourceCategory],
    structural: &Classification,
    tool_name: &str,
    arguments: &Arguments,
    environment_tier: EnvironmentTier,
) -> RiskProfile {
    let mut risk = RiskProfile {
        production: environment_tier == EnvironmentTier::Production
            || resources.contains(&ResourceCategory::ProductionSystem),
        credential_access: !structural.credentials.is_empty()
            || resources.contains(&ResourceCategory::Credential)
            || resources.contains(&ResourceCategory::Secret),
        sensitive_data_access: resources.contains(&ResourceCategory::Pii)
            || resources.contains(&ResourceCategory::FinancialData)
            || structural.data_classification.sensitivity >= Sensitivity::Confidential,
        external_destination: structural.destination.is_some(),
        ..RiskProfile::default()
    };

    risk.destructive = matches!(
        action,
        ActionCategory::Delete | ActionCategory::Deploy | ActionCategory::Escalate
    ) || command_or_statement_implies_destruction(structural, arguments);

    risk.irreversible = matches!(action, ActionCategory::Delete | ActionCategory::Deploy)
        || sql_implies_irreversible(database_statement(arguments).as_deref());

    risk.privileged = matches!(
        action,
        ActionCategory::Escalate | ActionCategory::Authenticate
    ) || privileged_path(&structural.target_resource)
        || privileged_command(structural.target_resource.as_ref());

    risk.bulk_operation = bulk_signals(tool_name, arguments, &structural.target_resource);

    let _ = tool_name; // reserved for future weighted signals; name alone never decides.

    risk
}

/* ------------------------------------------------------------------------ */
/* Signal helpers — structural first, names as hints only                     */
/* ------------------------------------------------------------------------ */

fn semantic_hint(tool_name: &str, fragments: &[&str]) -> bool {
    let lowered = tool_name.to_ascii_lowercase();
    fragments.iter().any(|fragment| lowered.contains(fragment))
}

fn create_like(tool_name: &str, arguments: &Arguments) -> bool {
    semantic_hint(tool_name, &["create", "mkdir", "touch", "insert"])
        || arguments
            .string_field("mode")
            .is_some_and(|mode| mode.eq_ignore_ascii_case("create"))
}

fn target_path(target: &Option<Resource>) -> Option<&str> {
    match target {
        Some(Resource::File { path }) | Some(Resource::Directory { path }) => Some(path.as_str()),
        Some(Resource::Command { raw, .. }) => Some(raw.as_str()),
        _ => None,
    }
}

fn classify_path(set: &mut BTreeSet<ResourceCategory>, path: &str) {
    let lowered = path.to_ascii_lowercase();
    if lowered.contains(".ssh")
        || lowered.contains(".env")
        || lowered.contains(".aws")
        || lowered.contains("credentials")
        || lowered.contains("secret")
    {
        set.insert(ResourceCategory::Credential);
        set.insert(ResourceCategory::Secret);
    }
    if lowered.contains("/src/")
        || lowered.ends_with(".rs")
        || lowered.ends_with(".ts")
        || lowered.ends_with(".py")
        || lowered.contains(".git/")
    {
        set.insert(ResourceCategory::SourceCode);
    }
    if lowered.contains("/etc/") || lowered.contains("/prod/") || lowered.contains("production") {
        set.insert(ResourceCategory::ProductionSystem);
    }
}

fn command_implies(found: ActionCategory, fallback: ActionCategory) -> ActionCategory {
    if found == ActionCategory::Unknown {
        fallback
    } else {
        found
    }
}

fn category_from_command(command: &str) -> ActionCategory {
    let lowered = command.to_ascii_lowercase();
    if lowered.contains("curl ")
        || lowered.contains("wget ")
        || lowered.contains("fetch(")
        || lowered.contains("http://")
        || lowered.contains("https://")
    {
        return ActionCategory::NetworkRequest;
    }
    if lowered.contains("rm ")
        || lowered.contains("unlink")
        || lowered.contains("drop table")
        || lowered.contains("truncate")
    {
        return ActionCategory::Delete;
    }
    if lowered.contains("sudo ")
        || lowered.contains("chmod ")
        || lowered.contains("chown ")
        || lowered.contains("runas")
    {
        return ActionCategory::Escalate;
    }
    if lowered.contains("deploy") || lowered.contains("kubectl apply") {
        return ActionCategory::Deploy;
    }
    ActionCategory::Execute
}

fn database_statement(arguments: &Arguments) -> Option<String> {
    arguments
        .first_string_field(["query", "sql", "statement"])
        .map(|(_, value)| value.to_string())
        .or_else(|| {
            arguments
                .value()
                .get("arguments")
                .and_then(|nested| nested.as_str())
                .map(str::to_string)
        })
}

fn sql_implies_write(statement: &str) -> bool {
    let lowered = statement.to_ascii_lowercase();
    [
        "insert ",
        "update ",
        "alter ",
        "create ",
        "drop ",
        "truncate ",
    ]
    .iter()
    .any(|verb| lowered.contains(verb))
}

fn sql_implies_delete(statement: &str) -> bool {
    let lowered = statement.to_ascii_lowercase();
    lowered.contains("delete ") || lowered.contains("drop ")
}

fn sql_implies_irreversible(statement: Option<&str>) -> bool {
    statement.is_some_and(|sql| {
        let lowered = sql.to_ascii_lowercase();
        lowered.contains("drop ") || lowered.contains("truncate ")
    })
}

fn command_or_statement_implies_destruction(
    structural: &Classification,
    arguments: &Arguments,
) -> bool {
    if let Some(Resource::Command { raw, .. }) = &structural.target_resource {
        if category_from_command(raw) == ActionCategory::Delete {
            return true;
        }
    }
    sql_implies_delete(database_statement(arguments).as_deref().unwrap_or(""))
}

fn privileged_path(target: &Option<Resource>) -> bool {
    target_path(target).is_some_and(|path| {
        let lowered = path.to_ascii_lowercase();
        lowered.starts_with("/etc/") || lowered.contains("/root/")
    })
}

fn privileged_command(target: Option<&Resource>) -> bool {
    matches!(target, Some(Resource::Command { raw, .. }) if {
        let lowered = raw.to_ascii_lowercase();
        lowered.contains("sudo ") || lowered.contains("chmod ") || lowered.contains("chown ")
    })
}

fn bulk_signals(tool_name: &str, arguments: &Arguments, target: &Option<Resource>) -> bool {
    if semantic_hint(tool_name, &["glob", "bulk", "batch", "all_"]) {
        return true;
    }

    let payload = arguments.value().to_string().to_ascii_lowercase();
    if payload.contains("recursive")
        || payload.contains("\"*\"")
        || payload.contains("glob(")
        || payload.contains("rm -rf")
    {
        return true;
    }

    target_path(target).is_some_and(|path| path.contains('*') || path.ends_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Arguments, DataClassification, Runtime, Sensitivity, SourceRef};
    use crate::classify::classify;

    fn action_from(tool_name: &str, args: serde_json::Value) -> AgentAction {
        let arguments = Arguments::from_name_and_arguments(tool_name, &args);
        let structural = classify(tool_name, &arguments);
        let mut action = AgentAction::builder(tool_name, arguments)
            .source(SourceRef::new(Runtime::MCP_STDIO, "test"))
            .runtime(Runtime::MCP_STDIO)
            .tool_type(structural.tool_type)
            .operation(structural.operation)
            .target_resource(structural.target_resource)
            .destination(structural.destination)
            .data_classification(structural.data_classification)
            .credentials(structural.credentials)
            .build_unvalidated();
        action.refresh_security_classification();
        action
    }

    #[test]
    fn filesystem_read_maps_to_read_and_filesystem() {
        let action = action_from("read_file", serde_json::json!({"path": "/tmp/a.txt"}));
        assert_eq!(action.security.action, ActionCategory::Read);
        assert!(action
            .security
            .touches_resource(ResourceCategory::Filesystem));
        assert!(!action.security.risk.destructive);
    }

    #[test]
    fn delete_file_maps_to_delete_and_is_destructive() {
        let action = action_from("delete_file", serde_json::json!({"path": "/tmp/a.txt"}));
        assert_eq!(action.security.action, ActionCategory::Delete);
        assert!(action.security.risk.destructive);
        assert!(action.security.risk.irreversible);
    }

    #[test]
    fn shell_rm_is_classified_from_command_not_tool_name() {
        let action = action_from(
            "acme_runner",
            serde_json::json!({"command": "rm -rf /tmp/build"}),
        );
        assert_eq!(action.security.action, ActionCategory::Delete);
        assert!(action.security.risk.destructive);
    }

    #[test]
    fn network_fetch_is_network_request_with_external_service() {
        let action = action_from(
            "fetch",
            serde_json::json!({"url": "https://api.example.com/v1"}),
        );
        assert_eq!(action.security.action, ActionCategory::NetworkRequest);
        assert!(action
            .security
            .touches_resource(ResourceCategory::ExternalService));
        assert!(action.security.risk.external_destination);
    }

    #[test]
    fn sql_select_is_query_and_sql_delete_is_delete() {
        let select = action_from(
            "execute_sql",
            serde_json::json!({"query": "SELECT * FROM users"}),
        );
        assert_eq!(select.security.action, ActionCategory::Query);
        assert!(select.security.touches_resource(ResourceCategory::Database));

        let delete = action_from(
            "execute_sql",
            serde_json::json!({"query": "DELETE FROM users WHERE id = 1"}),
        );
        assert_eq!(delete.security.action, ActionCategory::Delete);
        assert!(delete.security.risk.destructive);
    }

    #[test]
    fn credential_path_sets_credential_access() {
        let action = action_from(
            "read_file",
            serde_json::json!({"path": "/Users/x/.ssh/id_rsa"}),
        );
        assert!(action
            .security
            .touches_resource(ResourceCategory::Credential));
        assert!(action.security.risk.credential_access);
    }

    #[test]
    fn production_tier_sets_production_risk() {
        let mut action = action_from("read_file", serde_json::json!({"path": "/tmp/a"}));
        action.identity.environment.tier = EnvironmentTier::Production;
        action.refresh_security_classification();
        assert!(action.security.risk.production);
        assert!(action
            .security
            .touches_resource(ResourceCategory::ProductionSystem));
    }

    #[test]
    fn deploy_release_tool_maps_to_deploy_category() {
        let action = action_from("deploy_release", serde_json::json!({"target": "prod"}));
        assert_eq!(action.security.action, ActionCategory::Deploy);
        assert!(action.security.risk.destructive);
    }

    #[test]
    fn same_semantics_for_different_provider_tool_names() {
        let mcp = action_from("read_file", serde_json::json!({"path": "/tmp/a"}));
        let openai = action_from("Read", serde_json::json!({"path": "/tmp/a"}));
        let generic = action_from("vendor_read_thing", serde_json::json!({"path": "/tmp/a"}));

        assert_eq!(mcp.security.action, ActionCategory::Read);
        assert_eq!(openai.security.action, ActionCategory::Read);
        assert_eq!(generic.security.action, ActionCategory::Read);
    }

    #[test]
    fn taxonomy_match_context_exposes_risk_and_resource_fields() {
        let action = action_from(
            "execute_sql",
            serde_json::json!({"query": "DROP TABLE users", "database": "prod"}),
        );
        let ctx = TaxonomyMatchContext::from_action(&action);

        assert_eq!(ctx.field("action"), Some("delete".to_string()));
        assert_eq!(ctx.field("resource.database"), Some("true".to_string()));
        assert_eq!(ctx.field("risk.destructive"), Some("true".to_string()));
    }

    #[test]
    fn bulk_glob_detected_from_argument_shape() {
        let action = action_from(
            "glob_file_search",
            serde_json::json!({"glob_pattern": "**/*.rs"}),
        );
        assert!(action.security.risk.bulk_operation);
    }
}
