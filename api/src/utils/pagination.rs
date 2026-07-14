/// Normalize a signed limit/offset pair while it is still signed.
pub fn signed_limit_offset(
    limit: Option<i64>,
    offset: Option<i64>,
    default_limit: i64,
    max_limit: i64,
) -> (i64, i64) {
    (
        limit.unwrap_or(default_limit).clamp(1, max_limit.max(1)),
        offset.unwrap_or(0).max(0),
    )
}

/// Normalize a one-based signed page and calculate its offset without
/// overflow. A huge page becomes a huge (but valid) empty-result offset.
pub fn signed_page(
    page: Option<i64>,
    limit: Option<i64>,
    default_limit: i64,
    max_limit: i64,
) -> (i64, i64, i64) {
    let page = page.unwrap_or(1).max(1);
    let limit = limit.unwrap_or(default_limit).clamp(1, max_limit.max(1));
    let offset = page.saturating_sub(1).saturating_mul(limit);
    (page, limit, offset)
}

/// Convert store-level signed pagination only after applying defensive bounds.
pub fn store_u64(limit: i64, offset: i64, max_limit: i64) -> (u64, u64) {
    (
        limit.clamp(1, max_limit.max(1)) as u64,
        offset.max(0) as u64,
    )
}

/// Normalize pagination used only for an already-materialized in-memory
/// collection. This preserves an established `limit=0` empty-page contract
/// without unchecked signed-to-`usize` casts.
pub fn signed_slice_window(
    limit: Option<i64>,
    offset: Option<i64>,
    default_limit: usize,
) -> (usize, usize) {
    let limit = limit.map_or(default_limit, |value| {
        usize::try_from(value.max(0)).unwrap_or(usize::MAX)
    });
    let offset = usize::try_from(offset.unwrap_or(0).max(0)).unwrap_or(usize::MAX);
    (limit, offset)
}

/// Normalize a zero-based unsigned page with saturating offset calculation.
pub fn zero_based_u64_page(
    page: Option<u64>,
    limit: Option<u64>,
    default_limit: u64,
    max_limit: u64,
) -> (u64, u64, u64) {
    let page = page.unwrap_or(0);
    let limit = limit.unwrap_or(default_limit).clamp(1, max_limit.max(1));
    let offset = page.saturating_mul(limit).min(i64::MAX as u64);
    (page, limit, offset)
}

/// Normalize a one-based unsigned page with saturating offset calculation.
pub fn one_based_u64_page(
    page: Option<u64>,
    limit: Option<u64>,
    default_limit: u64,
    max_limit: u64,
) -> (u64, u64, u64) {
    let page = page.unwrap_or(1).max(1);
    let limit = limit.unwrap_or(default_limit).clamp(1, max_limit.max(1));
    (
        page,
        limit,
        page.saturating_sub(1)
            .saturating_mul(limit)
            .min(i64::MAX as u64),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_pagination_is_bounded_before_conversion_and_multiplication() {
        assert_eq!(signed_limit_offset(Some(-1), Some(-9), 50, 100), (1, 0));
        assert_eq!(signed_limit_offset(Some(i64::MAX), None, 50, 100), (100, 0));
        assert_eq!(signed_page(Some(0), Some(0), 20, 100), (1, 1, 0));
        assert_eq!(
            signed_page(Some(i64::MAX), Some(100), 20, 100),
            (i64::MAX, 100, i64::MAX)
        );
        assert_eq!(store_u64(-1, -1, 100), (1, 0));
        assert_eq!(signed_slice_window(Some(0), Some(-1), 50), (0, 0));
    }

    #[test]
    fn unsigned_page_offset_saturates() {
        assert_eq!(zero_based_u64_page(Some(0), Some(0), 50, 100), (0, 1, 0));
        assert_eq!(
            zero_based_u64_page(Some(u64::MAX), Some(100), 50, 100),
            (u64::MAX, 100, i64::MAX as u64)
        );
        assert_eq!(one_based_u64_page(Some(0), Some(0), 20, 100), (1, 1, 0));
        assert_eq!(
            one_based_u64_page(Some(u64::MAX), Some(100), 20, 100),
            (u64::MAX, 100, i64::MAX as u64)
        );
    }
}
