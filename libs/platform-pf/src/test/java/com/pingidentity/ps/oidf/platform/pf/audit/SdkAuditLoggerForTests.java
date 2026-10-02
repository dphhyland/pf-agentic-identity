/*
 * PingFederate 13.1.3's audit logger service as it writes the log4j ThreadContext, for the SDK's LoggingUtil in tests.
 */
package com.pingidentity.ps.oidf.platform.pf.audit;

import com.pingidentity.sdk.internal.services.ServiceFactory;
import com.pingidentity.sdk.internal.services.interfaces.AuditLoggerService;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.logging.log4j.ThreadContext;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.xmlbinding.assertion.NameIDType;

/**
 * The service the SDK's {@code LoggingUtil} is given in these tests. PingFederate's own {@code AuditLoggerServiceImpl}
 * delegates to {@code org.sourceid.websso.AuditLogger}, whose class initialisation needs a booted server's libraries
 * (Apache MINA among them). So this implements the interface and does what {@code AuditLogger} does to the
 * {@code ThreadContext}, read from 13.1.3's bytecode with {@code javap} on 2026-10-01: each setter puts one key, the
 * SDK's {@code setProtocol} puts {@code ip} (the quirk the writer avoids), and {@code cleanup} removes every key of
 * {@code AuditLogger.MDC_KEY}, listed in {@link #MDC_KEYS}. It is put where the SDK's {@code ServiceFactory} caches
 * the implementations {@code ServiceLoader} found, so {@code LoggingUtil} itself is the SDK's, unchanged. {@code log}
 * keeps a copy of the context it was called with: the columns the record was written with.
 */
public final class SdkAuditLoggerForTests implements AuditLoggerService {
    /** {@code AuditLogger.MDC_KEY}'s keys in PingFederate 13.1.3, in declaration order. */
    static final List<String> MDC_KEYS = List.of("subject", "ip", "fullappurl", "app", "connectionid", "connectionname",
            "virtualserverid", "host", "protocol", "event", "role", "status", "localuserid", "attributes", "pfversion",
            "adapterid", "authenticationsourceid", "validatorid", "targetsessionid", "description", "requeststarttime",
            "responsetime", "tlsversion", "sessiongroupid", "sri", "uniqueuserkey", "inmessagetype", "initiator",
            "assertionid", "requestid", "responseid", "inresponseto", "inxmlmsg", "outxmlmsg", "outurl", "clientauthntype",
            "attrackingid", "accessgrantguid", "granttype", "requestjti", "atjti", "inachash", "outachash", "inathash",
            "outathash", "inrthash", "outrthash", "idtjti", "stspluginid", "authnsessionexpiry", "plugin_type",
            "plugin_version", "plugin_id", "policyname", "fragmentname");

    /** The single-key setters, by method name, and the key each puts. */
    private static final Map<String, String> SETTERS = Map.ofEntries(Map.entry("setDescription", "description"),
            Map.entry("setStatus", "status"), Map.entry("setUserName", "subject"), Map.entry("setPartnerId", "connectionid"),
            Map.entry("setInMessageContext", "inxmlmsg"), Map.entry("setOutMessageContext", "outxmlmsg"),
            Map.entry("setHost", "host"), Map.entry("setRemoteAddress", "ip"), Map.entry("setProtocol", "ip"),
            Map.entry("setRequestStartTime", "requeststarttime"), Map.entry("setEvent", "event"), Map.entry("setRole", "role"),
            Map.entry("setAccessTokenJti", "atjti"), Map.entry("setRequestJti", "requestjti"));

    /** The ThreadContext at the last {@code log}: the record's columns. */
    static final Map<String, String> LAST_RECORD = new HashMap<>();
    /** When set, {@code log} throws after recording, as a failing appender would. */
    static volatile boolean failNextLog;

    @Override
    public void init() {
        // AuditLogger.init: the node's host name, status success and the licence's major.minor version.
        ThreadContext.put("host", "test-node");
        ThreadContext.put("status", "success");
        ThreadContext.put("pfversion", "13.1");
    }

    @Override
    public void log(Log log, String message) {
        LAST_RECORD.clear();
        LAST_RECORD.putAll(ThreadContext.getImmutableContext());
        if (failNextLog) {
            failNextLog = false;
            throw new IllegalStateException("appender failed");
        }
    }

    @Override
    public void cleanup() {
        MDC_KEYS.forEach(ThreadContext::remove);
    }

    @Override
    public void updateResponseTime() {
        ThreadContext.put("responsetime", "0");
    }

    @Override
    public boolean isDescriptionBlank() {
        String description = ThreadContext.get("description");
        return description == null || description.isBlank();
    }

    @Override
    public String getEvent() {
        return ThreadContext.get("event");
    }

    private static void put(String setter, String value) {
        ThreadContext.put(SETTERS.get(setter), value);
    }

    @Override
    public void setDescription(String value) {
        put("setDescription", value);
    }

    @Override
    public void setStatus(String value) {
        put("setStatus", value);
    }

    @Override
    public void setUserName(String value) {
        put("setUserName", value);
    }

    @Override
    public void setUserName(Map<String, AttributeValue> attributes) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setUserName(NameIDType nameId) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setPartnerId(String value) {
        put("setPartnerId", value);
    }

    @Override
    public void setInMessageContext(String value) {
        put("setInMessageContext", value);
    }

    @Override
    public void setOutMessageContext(String value) {
        put("setOutMessageContext", value);
    }

    @Override
    public void setHost(String value) {
        put("setHost", value);
    }

    @Override
    public void setRemoteAddress(String value) {
        put("setRemoteAddress", value);
    }

    @Override
    public void setProtocol(String value) {
        put("setProtocol", value);
    }

    @Override
    public void setRequestStartTime(Long value) {
        put("setRequestStartTime", String.valueOf(value));
    }

    @Override
    public void setEvent(String value) {
        put("setEvent", value);
    }

    @Override
    public void setRole(String value) {
        put("setRole", value);
    }

    @Override
    public void setAccessTokenJti(String value) {
        put("setAccessTokenJti", value);
    }

    @Override
    public void setRequestJti(String value) {
        put("setRequestJti", value);
    }

    /** Makes {@code LoggingUtil} use this service from now on in this JVM. */
    @SuppressWarnings("unchecked")
    static void install() throws ReflectiveOperationException {
        Field cache = ServiceFactory.class.getDeclaredField("SERVICE_CACHE");
        cache.setAccessible(true);
        ((Map<Class<?>, List<Class<?>>>) cache.get(null)).put(AuditLoggerService.class, List.of(SdkAuditLoggerForTests.class));
    }
}
