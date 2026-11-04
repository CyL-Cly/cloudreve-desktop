//! File uploader module for Cloudreve sync
//!
//! This module provides chunked file upload functionality with support for
//! multiple storage providers, encryption, resumable uploads, and progress tracking.

mod chunk;
mod encrypt;
mod error;
mod progress;
mod providers;
mod session;

use anyhow::{Context, Result, bail};
pub use chunk::{ChunkProgress, ChunkUploader};
pub use error::{UploadError, UploadResult};
pub use progress::{ProgressCallback, ProgressUpdate};
pub use session::UploadSession;

use crate::inventory::InventoryDb;
use crate::uploader::providers::PolicyType;
use cloudreve_api::models::explorer::GetFileInfoService;
use cloudreve_api::models::uri::CrUri;
use cloudreve_api::{Client as CrClient, api::ExplorerApi};
use reqwest::Client as HttpClient;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Destination storage policy cache, keyed by the remote parent folder URI.
///
/// The 139 cloud driver requires the whole-file digest at session creation, so
/// the *target* policy has to be known before the session exists. Files inherit
/// their folder's storage policy, so one lookup per folder is enough. Entries
/// are never invalidated: a stale entry can only cost an unnecessary hash pass
/// (harmless) or be caught by the server when the policy requires hashes.
static DEST_POLICY_CACHE: LazyLock<Mutex<HashMap<String, (PolicyType, bool)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Resolve the storage policy that a new file under `remote_uri` will use.
///
/// Returns `(policy type, relay)`; `None` when the server cannot tell us, in
/// which case the upload proceeds exactly as before.
///
/// `extended_info.storage_policy` only reflects the *folder's own* bound policy
/// (`files.storage_policy_files`), which is NULL for every folder that simply
/// inherits from its owner's group. The server picks the real upload policy
/// with `getPreferredPolicy(ancestor)` -- the group policy of the folder owner
/// -- so an inherited folder reports no policy at all while the upload still
/// lands on a 139 policy. In that case we fall back to the nearest ancestor
/// that does carry an explicit policy, and if none does, we ask the server
/// directly by creating the session and reading back the policy it picked.
async fn resolve_destination_policy(
    cr_client: &Arc<CrClient>,
    remote_uri: &str,
) -> Option<(PolicyType, bool)> {
    let mut current = CrUri::new(remote_uri)
        .ok()
        .and_then(|uri| uri.parent().ok())
        .map(|uri| uri.to_string())
        .unwrap_or_else(|| remote_uri.to_string());

    loop {
        if let Ok(cache) = DEST_POLICY_CACHE.lock() {
            if let Some(cached) = cache.get(&current) {
                return Some(*cached);
            }
        }

        let info = match cr_client
            .get_file_info(&GetFileInfoService {
                uri: Some(current.clone()),
                id: None,
                extended: Some(true),
                folder_summary: None,
            })
            .await
        {
            Ok(info) => info,
            Err(e) => {
                debug!(
                    target: "uploader",
                    uri = %current,
                    error = %e,
                    "Failed to resolve destination storage policy, assuming defaults"
                );
                return None;
            }
        };

        // Walk up while the ancestor leaves the policy to inheritance.
        let policy = match info.extended_info.and_then(|e| e.storage_policy) {
            Some(policy) => policy,
            None => {
                let next = CrUri::new(&current).ok().and_then(|uri| uri.parent().ok());
                match next {
                    Some(uri) => {
                        let parent = uri.to_string();
                        if parent == current {
                            return None;
                        }
                        current = parent;
                        continue;
                    }
                    None => return None,
                }
            }
        };

        let resolved = (
            PolicyType::from_api(&policy.policy_type),
            policy.relay.unwrap_or(false),
        );

        debug!(
            target: "uploader",
            uri = %current,
            requested = %remote_uri,
            policy_type = ?resolved.0,
            relay = resolved.1,
            "Resolved destination storage policy"
        );

        if let Ok(mut cache) = DEST_POLICY_CACHE.lock() {
            cache.insert(current, resolved);
        }
        return Some(resolved);
    }
}

/// Configuration for the uploader
#[derive(Debug, Clone)]
pub struct UploaderConfig {
    /// Maximum number of retry attempts per chunk
    pub max_retries: u32,
    /// Base delay between retries (exponential backoff)
    pub retry_base_delay: Duration,
    /// Maximum delay between retries
    pub retry_max_delay: Duration,
    /// Request timeout for chunk uploads
    pub request_timeout: Duration,
}

impl Default for UploaderConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_base_delay: Duration::from_secs(1),
            retry_max_delay: Duration::from_secs(30),
            request_timeout: Duration::from_secs(60),
        }
    }
}

/// Parameters for initiating an upload
#[derive(Debug, Clone)]
pub struct UploadParams {
    /// Local file path
    pub local_path: PathBuf,
    /// Remote URI (cloudreve path)
    pub remote_uri: String,
    /// File size in bytes
    pub file_size: u64,
    /// File MIME type (optional)
    pub mime_type: Option<String>,
    /// Last modified timestamp (optional)
    pub last_modified: Option<i64>,
    /// Whether to overwrite existing file (creates new version)
    pub overwrite: bool,
    /// Previous version ETag (optional)
    pub previous_version: String,
    /// Task ID for linking with task queue
    pub task_id: String,
    /// Drive ID
    pub drive_id: String,
}

/// Main uploader struct
pub struct Uploader {
    /// Cloudreve API client for session management
    cr_client: Arc<CrClient>,
    /// HTTP client for direct uploads to storage providers
    http_client: HttpClient,
    /// Inventory database for persisting session state
    inventory: Arc<InventoryDb>,
    /// Uploader configuration
    config: UploaderConfig,
    /// Cancellation token for stopping uploads
    cancel_token: CancellationToken,
}

impl Uploader {
    /// Create a new uploader instance
    pub fn new(
        cr_client: Arc<CrClient>,
        inventory: Arc<InventoryDb>,
        config: UploaderConfig,
    ) -> Self {
        let http_client = HttpClient::builder()
            .connect_timeout(config.request_timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            cr_client,
            http_client,
            inventory,
            config,
            cancel_token: CancellationToken::new(),
        }
    }

    /// Create uploader with a custom cancellation token
    pub fn with_cancel_token(mut self, token: CancellationToken) -> Self {
        self.cancel_token = token;
        self
    }

    /// Upload a file with progress reporting
    ///
    /// This method handles:
    /// - Creating or resuming an upload session
    /// - Splitting the file into chunks
    /// - Uploading chunks with retries
    /// - Reporting progress
    /// - Persisting state for resumability
    /// - Completing the upload
    pub async fn upload<P: ProgressCallback + 'static>(
        &self,
        params: UploadParams,
        progress: P,
    ) -> Result<()> {
        info!(
            target: "uploader",
            local_path = %params.local_path.display(),
            remote_uri = %params.remote_uri,
            file_size = params.file_size,
            "Starting upload"
        );

        // Try to resume existing session or create new one
        let mut session = match self.get_or_create_session(&params).await? {
            Some(session) => {
                info!(
                    target: "uploader",
                    session_id = %session.session_id(),
                    "Found existing upload session, removing it"
                );
                if let Err(e) = self.delete_remote_session(&session).await {
                    warn!(
                        target: "uploader",
                        session_id = %session.session_id(),
                        error = %e,
                        "Failed to delete remote upload session, will continue with new session"
                    );
                }
                self.cleanup_session(&session).await?;
                self.create_session(&params).await?
            }
            None => {
                debug!(
                    target: "uploader",
                    "No existing session found, creating new one"
                );
                self.create_session(&params).await?
            }
        };

        // Create chunk uploader based on policy type
        let chunk_uploader = self.create_chunk_uploader(&session)?;

        // Upload all chunks
        let progress = Arc::new(progress);
        let result = chunk_uploader
            .upload_all(
                &params.local_path,
                &mut session,
                progress,
                &self.cancel_token,
            )
            .await;

        match result {
            Ok(()) => {
                // Complete the upload
                self.complete_upload(&session).await?;
                // Clean up session from database
                self.cleanup_session(&session).await?;
                info!(
                    target: "uploader",
                    local_path = %params.local_path.display(),
                    "Upload completed successfully"
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    target: "uploader",
                    local_path = %params.local_path.display(),
                    error = %e,
                    "Upload failed"
                );
                if let Err(e) = self.delete_remote_session(&session).await {
                    warn!(
                        target: "uploader",
                        local_path = %params.local_path.display(),
                        error = %e,
                        "Failed to delete remote upload session"
                    );
                }
                // Clean up session from database
                self.cleanup_session(&session).await?;
                Err(e.into())
            }
        }
    }

    /// Cancel the current upload
    #[allow(dead_code)]
    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    /// Check if upload is cancelled
    #[allow(dead_code)]
    pub fn is_cancelled(&self) -> bool {
        self.cancel_token.is_cancelled()
    }

    /// Get or create an upload session
    async fn get_or_create_session(
        &self,
        params: &UploadParams,
    ) -> UploadResult<Option<UploadSession>> {
        // Try to load existing session from database
        match self
            .inventory
            .get_upload_session_by_path(&params.local_path.to_string_lossy().to_string())
        {
            Ok(Some(session)) => {
                // Check if session is still valid
                if session.is_expired() {
                    info!(
                        target: "uploader",
                        task_id = %params.task_id,
                        "Existing session expired, will create new one"
                    );
                    // Delete expired session
                    let _ = self.inventory.delete_upload_session(&session.id);
                    Ok(None)
                } else {
                    Ok(Some(session))
                }
            }
            Ok(None) => Ok(None),
            Err(e) => {
                warn!(
                    target: "uploader",
                    task_id = %params.task_id,
                    error = %e,
                    "Failed to load existing session, will create new one"
                );
                Ok(None)
            }
        }
    }

    /// Create a new upload session via Cloudreve API
    async fn create_session(&self, params: &UploadParams) -> Result<UploadSession> {
        use cloudreve_api::models::explorer::UploadSessionRequest;

        // Policies that must receive the whole-file digest up front (139 cloud)
        // need the hashes computed before the session exists.
        let mut yun139_extras: Option<providers::UploadExtras> = None;
        if let Some((policy_type, relay)) =
            resolve_destination_policy(&self.cr_client, &params.remote_uri).await
        {
            if policy_type == PolicyType::Yun139 && !relay {
                yun139_extras = Some(
                    providers::prepare_upload_extras(params.local_path.clone(), params.file_size)
                        .await
                        .context("failed to compute 139 cloud content hash")?,
                );
            }
        }

        let request = UploadSessionRequest {
            uri: params.remote_uri.clone(),
            size: params.file_size as i64,
            policy_id: "".to_string(),
            last_modified: params.last_modified,
            previous: if params.previous_version.is_empty() {
                None
            } else {
                Some(params.previous_version.clone())
            },
            entity_type: if params.overwrite {
                Some("version".to_string())
            } else {
                None
            },
            mime_type: params.mime_type.clone(),
            metadata: None,
            encryption_supported: Some(vec![
                cloudreve_api::models::explorer::EncryptionCipher::Aes256Ctr,
            ]),
            content_hash: yun139_extras.as_ref().map(|e| e.content_hash.clone()),
            chunk_size: yun139_extras.as_ref().map(|e| e.chunk_size as i64),
            part_hashes: yun139_extras.as_ref().map(|e| e.part_hashes.clone()),
        };

        let credential = self
            .cr_client
            .create_upload_session(&request)
            .await
            .context("failed to create upload session")?;

        // The part boundaries are baked into `part_hashes`, so a different chunk
        // size from the server would silently corrupt the upload.
        if let Some(extras) = &yun139_extras {
            if credential.chunk_size as u64 != extras.chunk_size {
                bail!(
                    "139 cloud accepted chunk_size {} but the hash states were built for {}",
                    credential.chunk_size,
                    extras.chunk_size
                );
            }
            if credential.encrypt_metadata.is_some() {
                bail!(
                    "139 cloud direct upload does not support client side encryption, \
                     disable encryption on the storage policy"
                );
            }
        }

        debug!(
            target: "uploader",
            session_id = %credential.session_id,
            chunk_size = credential.chunk_size,
            "Upload session created"
        );

        // Create session object
        let session = UploadSession::new(
            params.task_id.clone(),
            params.drive_id.clone(),
            params.local_path.to_string_lossy().to_string(),
            params.remote_uri.clone(),
            params.file_size,
            credential,
        );

        // Persist session to database
        self.inventory
            .insert_upload_session(&session)
            .map_err(|e| UploadError::DatabaseError(e.to_string()))?;

        Ok(session)
    }

    /// Create appropriate chunk uploader based on policy type
    fn create_chunk_uploader(&self, session: &UploadSession) -> UploadResult<ChunkUploader> {
        let policy_type = if session.is_relay() {
            providers::PolicyType::Local
        } else {
            session.policy_type()
        };
        let uploader = ChunkUploader::new(
            self.http_client.clone(),
            self.cr_client.clone(),
            policy_type,
            self.config.clone(),
        );
        Ok(uploader)
    }

    /// Complete the upload (provider-specific finalization)
    async fn complete_upload(&self, session: &UploadSession) -> Result<()> {
        let policy_type = session.policy_type();
        debug!(
            target: "uploader",
            session_id = %session.session_id(),
            policy_type = ?policy_type,
            "Completing upload"
        );

        providers::complete_upload(&self.http_client, &self.cr_client, session).await
    }

    /// Clean up session from database
    async fn cleanup_session(&self, session: &UploadSession) -> UploadResult<()> {
        self.inventory
            .delete_upload_session(&session.id)
            .map_err(|e| UploadError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Delete the remote upload session (cancel on server side)
    pub async fn delete_remote_session(&self, session: &UploadSession) -> UploadResult<()> {
        use cloudreve_api::models::explorer::DeleteUploadSessionService;

        let request = DeleteUploadSessionService {
            id: session.session_id().to_string(),
            uri: session.remote_uri.clone(),
        };

        self.cr_client
            .delete_upload_session(&request)
            .await
            .map_err(|e| UploadError::SessionDeletionFailed(e.to_string()))?;

        Ok(())
    }
}
