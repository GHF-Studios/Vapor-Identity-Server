use sqlx::SqlitePool;

use crate::providers::SteamAppOwnership;

pub(crate) async fn cached_steam_entitlement(
    pool: &SqlitePool,
    steam_id64: &str,
    product_id: &str,
    now: i64,
) -> Result<Option<(SteamAppOwnership, i64)>, sqlx::Error> {
    let row = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT active, permanent, expires_at_unix
         FROM steam_product_entitlement_cache
         WHERE steam_id64 = ? AND product_id = ? AND expires_at_unix > ?",
    )
    .bind(steam_id64)
    .bind(product_id)
    .bind(now)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(active, permanent, expires_at)| {
        (
            SteamAppOwnership {
                active: active != 0,
                permanent: permanent != 0,
            },
            expires_at,
        )
    }))
}

pub(crate) async fn cache_steam_entitlement(
    pool: &SqlitePool,
    steam_id64: &str,
    product_id: &str,
    ownership: SteamAppOwnership,
    checked_at: i64,
    expires_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO steam_product_entitlement_cache(
            steam_id64, product_id, active, permanent, checked_at_unix, expires_at_unix
         ) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(steam_id64, product_id) DO UPDATE SET
            active = excluded.active,
            permanent = excluded.permanent,
            checked_at_unix = excluded.checked_at_unix,
            expires_at_unix = excluded.expires_at_unix",
    )
    .bind(steam_id64)
    .bind(product_id)
    .bind(if ownership.active { 1_i64 } else { 0_i64 })
    .bind(if ownership.permanent { 1_i64 } else { 0_i64 })
    .bind(checked_at)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}
