package com.pingidentity.ps.oidf.warassembler;

/**
 * The assembler will not produce a war, and says why. The message is printed as it stands, so it names the
 * problem and, where there is one, what to do about it.
 */
final class Refusal extends Exception {
    private static final long serialVersionUID = 1L;

    /** A usage error: the arguments were wrong, and nothing was touched. */
    static final int USAGE = 2;
    /** A refusal: the inputs are not ones a war may be built from, and no output war is left behind. */
    static final int REFUSED = 1;

    private final int exitCode;

    Refusal(String message) {
        this(REFUSED, message);
    }

    Refusal(int exitCode, String message) {
        super(message);
        this.exitCode = exitCode;
    }

    int exitCode() {
        return exitCode;
    }
}
