/*
 * The Federation Entity Keys this entity no longer signs with.
 */
package com.pingidentity.ps.oidf.federation;

import java.util.List;
import java.util.Map;

/**
 * What the historical keys endpoint (OpenID Federation 1.0 §8.7) publishes: each key this entity signed with before, as a
 * public JWK with its {@code kid}, {@code exp}, its {@code iat} when known, and a {@code revoked} object when it was
 * revoked. {@code com.pingidentity.ps.oidf.keyhistory.KeyHistory} implements it over the recorded history.
 */
public interface HistoricalKeys {

    /** The retired keys, oldest first; empty before the first rotation. */
    List<Map<String, Object>> keys();
}
