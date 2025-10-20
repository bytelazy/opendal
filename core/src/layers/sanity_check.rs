// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use std::fmt::Debug;
use std::fmt::Formatter;
use std::sync::Arc;

use crate::raw::oio;
use crate::raw::*;
use crate::*;

/// Add a sanity check layer for every accessor to guard against
/// unexpected responses returned by services.
///
/// This layer validates the metadata returned from operations such
/// as `stat` and `list` to ensure they satisfy OpenDAL's invariants.
/// When a service responds with malformed metadata (for example,
/// reporting a directory entry without a trailing slash), OpenDAL
/// will now return an `Unexpected` error instead of continuing with
/// potentially undefined behaviour.
#[derive(Default)]
pub struct SanityCheckLayer;

impl<A: Access> Layer<A> for SanityCheckLayer {
    type LayeredAccess = SanityCheckAccessor<A>;

    fn layer(&self, inner: A) -> Self::LayeredAccess {
        let info = inner.info();
        SanityCheckAccessor { info, inner }
    }
}

pub struct SanityCheckAccessor<A: Access> {
    info: Arc<AccessorInfo>,
    inner: A,
}

impl<A: Access> Debug for SanityCheckAccessor<A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SanityCheckAccessor")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<A: Access> LayeredAccess for SanityCheckAccessor<A> {
    type Inner = A;
    type Reader = A::Reader;
    type Writer = A::Writer;
    type Lister = SanityCheckLister<A::Lister>;
    type Deleter = A::Deleter;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    fn info(&self) -> Arc<AccessorInfo> {
        self.info.clone()
    }

    async fn read(&self, path: &str, args: OpRead) -> Result<(RpRead, Self::Reader)> {
        self.inner.read(path, args).await
    }

    async fn write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::Writer)> {
        self.inner.write(path, args).await
    }

    async fn stat(&self, path: &str, args: OpStat) -> Result<RpStat> {
        let rp = self.inner.stat(path, args).await?;
        let meta = rp.into_metadata();

        sanity_check_path_mode(self.info.as_ref(), Operation::Stat, path, path, meta.mode())?;

        Ok(RpStat::new(meta))
    }

    async fn delete(&self) -> Result<(RpDelete, Self::Deleter)> {
        self.inner.delete().await
    }

    async fn list(&self, path: &str, args: OpList) -> Result<(RpList, Self::Lister)> {
        let (rp, lister) = self.inner.list(path, args).await?;
        Ok((rp, SanityCheckLister::new(self.info.clone(), path, lister)))
    }
}

pub struct SanityCheckLister<L> {
    info: Arc<AccessorInfo>,
    list_path: String,
    inner: L,
}

impl<L> SanityCheckLister<L> {
    fn new(info: Arc<AccessorInfo>, list_path: &str, inner: L) -> Self {
        Self {
            info,
            list_path: list_path.to_string(),
            inner,
        }
    }
}

impl<L: oio::List> oio::List for SanityCheckLister<L> {
    async fn next(&mut self) -> Result<Option<oio::Entry>> {
        match self.inner.next().await? {
            Some(entry) => {
                sanity_check_path_mode(
                    self.info.as_ref(),
                    Operation::List,
                    &self.list_path,
                    entry.path(),
                    entry.mode(),
                )?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }
}

fn sanity_check_path_mode(
    info: &AccessorInfo,
    op: Operation,
    context_path: &str,
    target_path: &str,
    mode: EntryMode,
) -> Result<()> {
    match mode {
        EntryMode::Unknown => Err(unexpected_response(
            info,
            op,
            target_path,
            context_path,
            "metadata is missing an entry mode",
        )),
        EntryMode::DIR => {
            if !is_directory_path(target_path) {
                Err(unexpected_response(
                    info,
                    op,
                    target_path,
                    context_path,
                    format!(
                        "path `{target_path}` was reported as a directory but does not end with `/`"
                    ),
                ))
            } else {
                Ok(())
            }
        }
        EntryMode::FILE => {
            if is_directory_path(target_path) {
                Err(unexpected_response(
                    info,
                    op,
                    target_path,
                    context_path,
                    format!("path `{target_path}` was reported as a file but ends with `/`"),
                ))
            } else {
                Ok(())
            }
        }
    }
}

fn is_directory_path(path: &str) -> bool {
    path == "/" || path.ends_with('/')
}

fn unexpected_response(
    info: &AccessorInfo,
    op: Operation,
    target_path: &str,
    context_path: &str,
    detail: impl Into<String>,
) -> Error {
    let err = Error::new(
        ErrorKind::Unexpected,
        format!(
            "service {} returned an unexpected {} response: {}",
            info.scheme(),
            op,
            detail.into()
        ),
    )
    .with_operation(op)
    .with_context("path", target_path);

    if op == Operation::List {
        err.with_context("list_path", context_path)
    } else {
        err.with_context("context_path", context_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_info() -> AccessorInfo {
        let info = AccessorInfo::default();
        info.set_scheme("test");
        info
    }

    #[test]
    fn sanity_check_accepts_valid_file_metadata() {
        let info = build_info();
        sanity_check_path_mode(&info, Operation::Stat, "file", "file", EntryMode::FILE)
            .expect("valid file metadata should pass");
    }

    #[test]
    fn sanity_check_accepts_valid_dir_metadata() {
        let info = build_info();
        sanity_check_path_mode(&info, Operation::Stat, "dir/", "dir/", EntryMode::DIR)
            .expect("valid dir metadata should pass");
    }

    #[test]
    fn sanity_check_rejects_unknown_mode() {
        let info = build_info();
        let err =
            sanity_check_path_mode(&info, Operation::Stat, "file", "file", EntryMode::Unknown)
                .expect_err("unknown mode should fail");
        assert_eq!(err.kind(), ErrorKind::Unexpected);
    }

    #[test]
    fn sanity_check_rejects_dir_without_trailing_slash() {
        let info = build_info();
        let err = sanity_check_path_mode(&info, Operation::Stat, "dir", "dir", EntryMode::DIR)
            .expect_err("dir without trailing slash should fail");
        assert_eq!(err.kind(), ErrorKind::Unexpected);
    }

    #[test]
    fn sanity_check_rejects_file_with_trailing_slash() {
        let info = build_info();
        let err = sanity_check_path_mode(&info, Operation::Stat, "dir/", "dir/", EntryMode::FILE)
            .expect_err("file with trailing slash should fail");
        assert_eq!(err.kind(), ErrorKind::Unexpected);
    }

    #[test]
    fn sanity_check_allows_root_directory() {
        let info = build_info();
        sanity_check_path_mode(&info, Operation::Stat, "/", "/", EntryMode::DIR)
            .expect("root directory should pass");
    }

    #[test]
    fn sanity_check_rejects_root_as_file() {
        let info = build_info();
        let err = sanity_check_path_mode(&info, Operation::Stat, "/", "/", EntryMode::FILE)
            .expect_err("root marked as file should fail");
        assert_eq!(err.kind(), ErrorKind::Unexpected);
    }
}
