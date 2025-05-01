/// We won't backfill further then 3 months of blocks back
///
/// Since CL clients are only required to serve 4-5 months of history
/// 3 months of backfill is a reasonable limit.
///
/// If we need to generate files older then that, we can always
/// use the single generator to generate them.
pub const MAX_ALLOWED_BLOCK_BACKFILL_SIZE: u64 = (3 * 30 * 24 * 60 * 60) / 12;
