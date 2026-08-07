package com.metricflow.api.security;

import org.springframework.core.env.Environment;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.function.Predicate;

/**
 * Everything the configuration checks are allowed to look at. Supplying these as data keeps each
 * check a pure function of its input and therefore testable without a Spring context.
 */
public final class ConfigCheckContext {

    private final Environment environment;
    private final String springBootVersion;
    private final int bytecodeMajorVersion;
    private final String javaRuntimeVersion;
    private final Predicate<String> classPresent;

    public ConfigCheckContext(Environment environment,
                              String springBootVersion,
                              int bytecodeMajorVersion,
                              String javaRuntimeVersion,
                              Predicate<String> classPresent) {
        this.environment = Objects.requireNonNull(environment, "environment");
        this.springBootVersion = springBootVersion;
        this.bytecodeMajorVersion = bytecodeMajorVersion;
        this.javaRuntimeVersion = javaRuntimeVersion;
        this.classPresent = Objects.requireNonNull(classPresent, "classPresent");
    }

    public Environment getEnvironment() {
        return environment;
    }

    public String getSpringBootVersion() {
        return springBootVersion;
    }

    /**
     * Class file major version the application itself was compiled to: 55 for Java 11, 61 for 17,
     * 65 for 21. This is what matters for a language-level baseline, and it can differ from the JDK
     * that happens to be running the process.
     */
    public int getBytecodeMajorVersion() {
        return bytecodeMajorVersion;
    }

    public String getJavaRuntimeVersion() {
        return javaRuntimeVersion;
    }

    public boolean isClassPresent(String className) {
        return classPresent.test(className);
    }

    public String property(String key) {
        return environment.getProperty(key);
    }

    public boolean isProfileActive(String profile) {
        for (String active : environment.getActiveProfiles()) {
            if (profile.equalsIgnoreCase(active)) {
                return true;
            }
        }
        return false;
    }

    /** Reads the class file major version from a compiled application class. */
    public static int readBytecodeMajorVersion(Class<?> type) {
        String resource = type.getName().replace('.', '/') + ".class";
        try (InputStream in = type.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                return -1;
            }
            DataInputStream data = new DataInputStream(in);
            if (data.readInt() != 0xCAFEBABE) {
                return -1;
            }
            data.readUnsignedShort();
            return data.readUnsignedShort();
        } catch (IOException e) {
            return -1;
        }
    }

    /** Maps a class file major version to its Java feature release, or -1 when unknown. */
    public static int javaFeatureRelease(int majorVersion) {
        return majorVersion < 46 ? -1 : majorVersion - 44;
    }
}
