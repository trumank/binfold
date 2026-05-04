//! Hash abstraction for function/constraint GUIDs.
//!
//! All GUID computation goes through [`HashAlgo`]. Library users who don't use the
//! bundled `db` module can plug in their own algorithm. The bundled [`UuidV5`] impl
//! is what `db::Db` is pinned to.

use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;

use uuid::{Uuid, uuid};

/// A hash algorithm used to produce GUIDs.
///
/// `Key` is a per-domain salt (UUID namespace, hash seed, …). Domain keys are derived
/// from stable string labels via [`HashAlgo::key_from_name`], so impls only need to
/// describe how a name maps to a key — the labels themselves live on [`DomainTag`].
pub trait HashAlgo: 'static {
    /// Fixed-width output of the hash. This is what callers actually compare/store.
    type Digest: Copy + Eq + Ord + Hash + Default + fmt::Debug + Send + Sync + 'static;

    /// Per-domain salt produced by [`HashAlgo::key_from_name`].
    type Key: Copy;

    /// On-disk / on-wire byte width of [`Self::Digest`]. The DB layout uses this to
    /// compute fixed-record offsets, so it must match the length of the slice
    /// returned by [`Self::digest_bytes`] and consumed by [`Self::digest_from_bytes`].
    const DIGEST_SIZE: usize;

    fn oneshot(key: Self::Key, bytes: &[u8]) -> Self::Digest;
    fn key_from_name(name: &str) -> Self::Key;

    fn nil() -> Self::Digest;

    /// Stable byte view used when chaining one digest into another's input.
    fn digest_bytes(d: &Self::Digest) -> impl AsRef<[u8]>;

    /// Inverse of [`Self::digest_bytes`]. `bytes.len()` must equal [`Self::DIGEST_SIZE`].
    fn digest_from_bytes(bytes: &[u8]) -> Self::Digest;

    fn fmt_digest(d: &Self::Digest, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

/// A domain that can be hashed directly from raw bytes (i.e. its key is derived from
/// [`Self::NAME`] and `from_bytes` is meaningful).
pub trait DomainTag: 'static {
    const NAME: &'static str;
}

pub enum FunctionTag {}
impl DomainTag for FunctionTag {
    const NAME: &'static str = "function";
}

pub enum BasicBlockTag {}
impl DomainTag for BasicBlockTag {
    const NAME: &'static str = "basic_block";
}

pub enum SymbolTag {}
impl DomainTag for SymbolTag {
    const NAME: &'static str = "symbol";
}

pub enum ChildCallTag {}
impl DomainTag for ChildCallTag {
    const NAME: &'static str = "child_call";
}

pub enum ParentCallTag {}
impl DomainTag for ParentCallTag {
    const NAME: &'static str = "parent_call";
}

pub enum SymbolChildCallTag {}
impl DomainTag for SymbolChildCallTag {
    const NAME: &'static str = "symbol_child_call";
}

pub enum SymbolParentCallTag {}
impl DomainTag for SymbolParentCallTag {
    const NAME: &'static str = "symbol_parent_call";
}

pub enum DataConstTag {}
impl DomainTag for DataConstTag {
    const NAME: &'static str = "data_const";
}

/// Marker tag for constraint GUIDs. Constraint guids are always derived through one
/// of the sub-domain tags above, so this tag deliberately does *not* implement
/// [`DomainTag`].
pub enum ConstraintTag {}

/// Tagged digest. The phantom `Tag` makes it a type error to mix domains.
pub struct Guid<Tag, H: HashAlgo> {
    pub digest: H::Digest,
    _tag: PhantomData<fn() -> Tag>,
}

// Manual derives so the bounds land on `H::Digest`, not `H` itself.
impl<Tag, H: HashAlgo> Clone for Guid<Tag, H> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<Tag, H: HashAlgo> Copy for Guid<Tag, H> {}
impl<Tag, H: HashAlgo> Default for Guid<Tag, H> {
    fn default() -> Self {
        Self::from_digest(H::nil())
    }
}
impl<Tag, H: HashAlgo> PartialEq for Guid<Tag, H> {
    fn eq(&self, o: &Self) -> bool {
        self.digest == o.digest
    }
}
impl<Tag, H: HashAlgo> Eq for Guid<Tag, H> {}
impl<Tag, H: HashAlgo> PartialOrd for Guid<Tag, H> {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl<Tag, H: HashAlgo> Ord for Guid<Tag, H> {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.digest.cmp(&o.digest)
    }
}
impl<Tag, H: HashAlgo> Hash for Guid<Tag, H> {
    fn hash<S: std::hash::Hasher>(&self, s: &mut S) {
        self.digest.hash(s)
    }
}
impl<Tag, H: HashAlgo> fmt::Debug for Guid<Tag, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Guid").field(&self.digest).finish()
    }
}
impl<Tag, H: HashAlgo> fmt::Display for Guid<Tag, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        H::fmt_digest(&self.digest, f)
    }
}

impl<Tag, H: HashAlgo> Guid<Tag, H> {
    pub const fn from_digest(digest: H::Digest) -> Self {
        Self {
            digest,
            _tag: PhantomData,
        }
    }
    pub fn nil() -> Self {
        Self::default()
    }
}

impl<Tag: DomainTag, H: HashAlgo> Guid<Tag, H> {
    /// Hash raw bytes under this tag's domain key.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::from_digest(H::oneshot(H::key_from_name(Tag::NAME), bytes))
    }
}

pub type FunctionGuid<H> = Guid<FunctionTag, H>;
pub type BasicBlockGuid<H> = Guid<BasicBlockTag, H>;
pub type SymbolGuid<H> = Guid<SymbolTag, H>;
pub type ConstraintGuid<H> = Guid<ConstraintTag, H>;

impl<H: HashAlgo> SymbolGuid<H> {
    pub fn from_symbol(symbol_name: impl AsRef<str>) -> Self {
        Self::from_bytes(symbol_name.as_ref().as_bytes())
    }
}

impl<H: HashAlgo> ConstraintGuid<H> {
    fn derive<Domain: DomainTag, Src>(src: Guid<Src, H>) -> Self {
        Self::from_digest(H::oneshot(
            H::key_from_name(Domain::NAME),
            H::digest_bytes(&src.digest).as_ref(),
        ))
    }

    /// Constraint on call to target function.
    pub fn from_child_call(target: FunctionGuid<H>) -> Self {
        Self::derive::<ChildCallTag, _>(target)
    }
    /// Constraint on target calling this function.
    pub fn from_parent_call(target: FunctionGuid<H>) -> Self {
        Self::derive::<ParentCallTag, _>(target)
    }
    /// Constraint on call to target function (by symbol name).
    pub fn from_symbol_child_call(target: SymbolGuid<H>) -> Self {
        Self::derive::<SymbolChildCallTag, _>(target)
    }
    /// Constraint on target calling this function (by symbol name).
    pub fn from_symbol_parent_call(target: SymbolGuid<H>) -> Self {
        Self::derive::<SymbolParentCallTag, _>(target)
    }
    /// Constraint on reference to read-only data.
    pub fn from_data_const(data: &[u8]) -> Self {
        Self::from_digest(H::oneshot(H::key_from_name(DataConstTag::NAME), data))
    }
}

/// xxHash-64 implementation. Per-domain keys are the xxhash-64 of the domain name.
#[derive(Debug, Default, Clone, Copy)]
pub struct XxHash64;

impl HashAlgo for XxHash64 {
    type Digest = u64;
    type Key = u64;

    const DIGEST_SIZE: usize = 8;

    fn oneshot(key: u64, bytes: &[u8]) -> u64 {
        twox_hash::XxHash64::oneshot(key, bytes)
    }

    fn key_from_name(name: &str) -> u64 {
        twox_hash::XxHash64::oneshot(0, name.as_bytes())
    }

    fn nil() -> u64 {
        0
    }

    fn digest_bytes(d: &u64) -> impl AsRef<[u8]> {
        d.to_le_bytes()
    }

    fn digest_from_bytes(bytes: &[u8]) -> u64 {
        u64::from_le_bytes(bytes.try_into().unwrap())
    }

    fn fmt_digest(d: &u64, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", d)
    }
}

/// UUID v5 implementation. All per-domain namespaces are derived from a single root
/// namespace via `Uuid::new_v5(&ROOT, name.as_bytes())`.
#[derive(Debug, Default, Clone, Copy)]
pub struct UuidV5;

const UUIDV5_ROOT: Uuid = uuid!("c1a7f83a-38a2-4bed-b6a3-babc0df6860f");

impl HashAlgo for UuidV5 {
    type Digest = Uuid;
    type Key = Uuid;

    const DIGEST_SIZE: usize = 16;

    fn oneshot(key: Uuid, bytes: &[u8]) -> Uuid {
        Uuid::new_v5(&key, bytes)
    }

    fn key_from_name(name: &str) -> Uuid {
        Uuid::new_v5(&UUIDV5_ROOT, name.as_bytes())
    }

    fn nil() -> Uuid {
        Uuid::nil()
    }

    fn digest_bytes(d: &Uuid) -> impl AsRef<[u8]> {
        *d.as_bytes()
    }

    fn digest_from_bytes(bytes: &[u8]) -> Uuid {
        Uuid::from_bytes(bytes.try_into().unwrap())
    }

    fn fmt_digest(d: &Uuid, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(d, f)
    }
}
