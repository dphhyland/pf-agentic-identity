/*
 * The commons-logging route, in a class of its own.
 */
package com.pingidentity.ps.oidf.platform.log;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Lines through commons-logging. The only class in platform that names commons-logging: the JVM links it the
 * first time {@link PlatformLog} chooses it, which it does only when the loader can see commons-logging, so a
 * loader without it never loads this class and never fails for want of it.
 */
final class CommonsLoggingSink implements PlatformLog.Sink {
    private final Log log;

    private CommonsLoggingSink(Log log) {
        this.log = log;
    }

    static CommonsLoggingSink of(String name) {
        return new CommonsLoggingSink(LogFactory.getLog(name));
    }

    @Override
    public boolean isDebugEnabled() {
        return this.log.isDebugEnabled();
    }

    @Override
    public void log(PlatformLog.Level level, String message, Throwable thrown) {
        switch (level) {
            case DEBUG -> this.log.debug(message, thrown);
            case INFO -> this.log.info(message, thrown);
            case WARN -> this.log.warn(message, thrown);
            case ERROR -> this.log.error(message, thrown);
        }
    }
}
