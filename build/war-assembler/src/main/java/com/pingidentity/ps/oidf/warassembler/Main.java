package com.pingidentity.ps.oidf.warassembler;

/** {@code java -jar war-assembler.jar --filters FILTERS_XML STOCK_WAR MODULES JOSE4J_JAR OUT_WAR [PROFILE]}. */
public final class Main {
    private Main() {
    }

    public static void main(String[] args) {
        System.exit(Assembler.run(args, System.out, System.err));
    }
}
