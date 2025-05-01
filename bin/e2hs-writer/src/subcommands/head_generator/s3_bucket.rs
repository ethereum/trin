use std::path::PathBuf;

use anyhow::{anyhow, bail};
use aws_config::retry::RetryConfig;
use aws_sdk_s3::{
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart},
    Client as AWSClient,
};
use tokio::{fs::File, io::AsyncReadExt};
use tracing::info;

/// 100 MB
const TARGET_CHUNK_SIZE: usize = 100 * 1024 * 1024;

pub struct S3Bucket {
    aws_client: AWSClient,
    bucket_name: String,
}

impl S3Bucket {
    pub async fn new(bucket_name: String) -> Self {
        let aws_config = aws_config::from_env()
            .retry_config(RetryConfig::standard())
            .load()
            .await;
        Self {
            aws_client: AWSClient::new(&aws_config),
            bucket_name,
        }
    }

    /// Uploads file to S3 in a multipart upload.
    ///
    /// We use upload files in multiple parts because R2 was throwing an error when I tried to
    /// upload a whole file in one go.
    pub async fn upload_file_from_path(&self, path: &PathBuf) -> anyhow::Result<()> {
        info!("Starting upload for: {path:?}");

        let file_name = path
            .file_name()
            .ok_or(anyhow!("Failed to get file name"))?
            .to_str()
            .ok_or(anyhow!("Failed to convert file name to string"))?
            .to_string();

        info!("Resolved file name: {file_name}");

        let mut file = File::open(path).await?;
        let file_size = file.metadata().await?.len() as usize;

        info!("File size: {file_size} bytes");

        let mut full_data = vec![0u8; file_size];
        file.read_exact(&mut full_data).await?;

        let part_count = file_size.div_ceil(TARGET_CHUNK_SIZE);
        let chunk_size = file_size.div_ceil(part_count);

        info!("Splitting file into {part_count} parts, each with ~{chunk_size} bytes");

        let multipart_response = self
            .aws_client
            .create_multipart_upload()
            .bucket(&self.bucket_name)
            .key(&file_name)
            .send()
            .await?;

        let upload_id = multipart_response
            .upload_id()
            .ok_or_else(|| anyhow!("Missing upload ID"))?
            .to_string();

        info!("Multipart upload started with upload ID: {upload_id}");

        let mut completed_parts = Vec::new();
        for (part_number, chunk) in full_data.chunks(chunk_size).enumerate() {
            // s3 requires part numbers to start from 1
            let part_number = part_number + 1;
            info!("Uploading part {part_number} ({} bytes)...", chunk.len());

            let byte_stream = ByteStream::from(chunk.to_vec());
            let upload_part_response = self
                .aws_client
                .upload_part()
                .bucket(&self.bucket_name)
                .key(&file_name)
                .upload_id(&upload_id)
                .part_number(part_number as i32)
                .body(byte_stream)
                .send()
                .await?;

            let e_tag = upload_part_response
                .e_tag()
                .ok_or_else(|| anyhow!("Missing ETag in upload_part response"))?
                .to_string();

            info!("Uploaded part {part_number} with ETag: {e_tag}");

            completed_parts.push(
                CompletedPart::builder()
                    .e_tag(e_tag)
                    .part_number(part_number as i32)
                    .build(),
            );
        }

        info!("All parts uploaded. Finalizing upload...");

        let completed_upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();

        self.aws_client
            .complete_multipart_upload()
            .bucket(&self.bucket_name)
            .key(&file_name)
            .upload_id(upload_id)
            .multipart_upload(completed_upload)
            .send()
            .await?;

        info!("Upload of {file_name} completed successfully");

        Ok(())
    }

    pub async fn last_file_name(&self) -> anyhow::Result<String> {
        let mut continuation_token: Option<String> = None;
        let mut last_key: Option<String> = None;

        while let Ok(response) = self
            .aws_client
            .list_objects_v2()
            .bucket(&self.bucket_name)
            .set_continuation_token(continuation_token.clone())
            .send()
            .await
        {
            for object in response.contents() {
                if let Some(key) = object.key() {
                    last_key = Some(key.to_string());
                }
            }

            if let Some(true) = response.is_truncated() {
                continuation_token = response
                    .next_continuation_token()
                    .map(|str| str.to_string());
            } else {
                break;
            }
        }

        if let Some(last_file_name) = last_key {
            return Ok(last_file_name);
        }

        bail!("Failed to find the last file name uploaded to the bucket")
    }
}
