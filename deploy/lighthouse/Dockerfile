# OpenID Federation trust anchor / resolver (go-oidfed "lighthouse").
#
# Pinned by DIGEST, deliberately. An unpinned `:latest` is exactly what drifted and broke
# staging (a newer image began REQUIRING storage/signing config the old one defaulted). This
# digest is also the build proven to invalidate the /resolve cache on subordinate mutations
# (DELETE and PUT :id/status are wrapped in withCacheWipe), so revoke/suspend take effect
# immediately. Keep staging and production on the SAME digest — that is the whole point.
#
# All runtime config is environment variables (see vars.<env>.env). Federation endpoints
# (fetch/list/resolve/trust_mark) are CONFIG-GATED by path via LH_ENDPOINTS_*_PATH — without
# them the endpoints 404. Persistent state (anchor key + subordinate DB) lives on a Railway
# volume mounted at /data (LH_STORAGE_DATA_DIR); the volume is a pre-existing project resource.
FROM oidfed/lighthouse@sha256:fd4d64df17d582d4e2f4e47f17a585d4a86cf8e66bf18d833515817557f973e5
