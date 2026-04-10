package analyze;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.Locale;
import java.util.stream.Stream;

public final class SootCacheSupport {
    public static final String MODE_OFF = "off";
    public static final String MODE_READ_ONLY = "readonly";
    public static final String MODE_READ_WRITE = "readwrite";
    public static final String HASH_BUCKET_DIR = "soot_cache_hash";

    private SootCacheSupport() {
    }

    public static String normalizeMode(String rawMode) {
        if (rawMode == null || rawMode.trim().isEmpty()) {
            return MODE_OFF;
        }
        String mode = rawMode.trim().toLowerCase(Locale.ROOT);
        if ("ro".equals(mode) || "read-only".equals(mode) || "read_only".equals(mode)) {
            return MODE_READ_ONLY;
        }
        if ("rw".equals(mode) || "read-write".equals(mode) || "read_write".equals(mode)) {
            return MODE_READ_WRITE;
        }
        if (MODE_OFF.equals(mode) || MODE_READ_ONLY.equals(mode) || MODE_READ_WRITE.equals(mode)) {
            return mode;
        }
        return MODE_OFF;
    }

    public static boolean isCacheEnabled(Configuration config) {
        if (config == null) {
            return false;
        }
        if (config.getCacheDir() == null || config.getCacheDir().trim().isEmpty()) {
            return false;
        }
        return !MODE_OFF.equals(normalizeMode(config.getCacheMode()));
    }

    public static boolean isReadWrite(Configuration config) {
        return MODE_READ_WRITE.equals(normalizeMode(config.getCacheMode()));
    }

    public static File getEntryDir(Configuration config, String domain, File sourceFile) throws IOException {
        if (!isCacheEnabled(config) || sourceFile == null) {
            return null;
        }
        String key = buildContentHash(sourceFile);
        return getHashEntryDir(config, domain, key);
    }

    public static File getAliasEntryDirIfReady(Configuration config, String domain, File sourceFile) throws IOException {
        if (!isCacheEnabled(config) || sourceFile == null) {
            return null;
        }
        String hash = readAliasHash(config, domain, sourceFile);
        if (hash.isEmpty()) {
            return null;
        }
        File entryDir = resolveEntryDirByHash(config, domain, hash);
        return isReady(entryDir) ? entryDir : null;
    }

    public static void registerAlias(Configuration config, String domain, File sourceFile, File entryDir) throws IOException {
        if (!isCacheEnabled(config) || sourceFile == null || entryDir == null) {
            return;
        }
        String previousHash = readAliasHash(config, domain, sourceFile);
        File aliasFile = getAliasFile(config, domain, sourceFile);
        File aliasParent = aliasFile.getParentFile();
        if (!aliasParent.exists() && !aliasParent.mkdirs()) {
            throw new IOException("Failed to create alias directory: " + aliasParent.getAbsolutePath());
        }
        String currentHash = entryDir.getName();
        Files.write(aliasFile.toPath(), currentHash.getBytes(StandardCharsets.UTF_8));
        File lowerAlias = getLowerCaseAliasFile(config, domain, sourceFile);
        if (!lowerAlias.getAbsolutePath().equals(aliasFile.getAbsolutePath()) && lowerAlias.exists()) {
            Files.deleteIfExists(lowerAlias.toPath());
        }
        if (previousHash != null && !previousHash.isEmpty() && !previousHash.equals(currentHash)) {
            cleanupHashIfUnreferenced(config, domain, previousHash);
        }
    }

    public static String readAliasHash(Configuration config, String domain, File sourceFile) throws IOException {
        if (!isCacheEnabled(config) || sourceFile == null) {
            return "";
        }
        File aliasFile = getAliasFile(config, domain, sourceFile);
        if (aliasFile.exists()) {
            return new String(Files.readAllBytes(aliasFile.toPath()), StandardCharsets.UTF_8).trim();
        }
        File lowerAlias = getLowerCaseAliasFile(config, domain, sourceFile);
        if (lowerAlias.exists()) {
            return new String(Files.readAllBytes(lowerAlias.toPath()), StandardCharsets.UTF_8).trim();
        }
        return "";
    }

    public static File resolveEntryDirByHash(Configuration config, String domain, String hash) {
        if (config == null || hash == null || hash.trim().isEmpty()) {
            return null;
        }
        String normalizedHash = hash.trim();
        File newLayout = getHashEntryDir(config, domain, normalizedHash);
        if (newLayout.exists()) {
            return newLayout;
        }
        File legacyLayout = getLegacyHashEntryDir(config, domain, normalizedHash);
        if (legacyLayout.exists()) {
            return legacyLayout;
        }
        return newLayout;
    }

    public static String buildContentHash(File sourceFile) throws IOException {
        MessageDigest md = sha256Digest();
        try (InputStream in = Files.newInputStream(sourceFile.toPath())) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) > 0) {
                md.update(buffer, 0, read);
            }
        }
        return toHex(md.digest());
    }

    public static File getJimpleDir(File entryDir) {
        return new File(entryDir, "jimple");
    }

    public static File getReadyFile(File entryDir) {
        return new File(entryDir, ".ready");
    }

    public static boolean isReady(File entryDir) {
        if (entryDir == null) {
            return false;
        }
        File ready = getReadyFile(entryDir);
        File jimpleDir = getJimpleDir(entryDir);
        return ready.exists() && jimpleDir.exists() && jimpleDir.isDirectory();
    }

    public static void prepareJimpleOutputDir(File entryDir) throws IOException {
        if (entryDir == null) {
            return;
        }
        File jimpleDir = getJimpleDir(entryDir);
        if (jimpleDir.exists()) {
            deleteDirectory(jimpleDir.toPath());
        }
        if (!jimpleDir.mkdirs() && !jimpleDir.exists()) {
            throw new IOException("Failed to create cache directory: " + jimpleDir.getAbsolutePath());
        }
    }

    public static void markReady(File entryDir, String metadata) throws IOException {
        if (entryDir == null) {
            return;
        }
        if (!entryDir.exists() && !entryDir.mkdirs()) {
            throw new IOException("Failed to create cache entry dir: " + entryDir.getAbsolutePath());
        }
        String content = metadata == null ? "" : metadata;
        Files.write(getReadyFile(entryDir).toPath(), content.getBytes(StandardCharsets.UTF_8));
    }

    public static void deleteDirectory(Path dir) throws IOException {
        if (dir == null || !Files.exists(dir)) {
            return;
        }
        Files.walk(dir)
                .sorted(Comparator.reverseOrder())
                .forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (IOException ignored) {
                    }
                });
    }

    private static File getHashEntryDir(Configuration config, String domain, String hash) {
        return new File(new File(getDomainDir(config, domain), HASH_BUCKET_DIR), hash);
    }

    private static File getLegacyHashEntryDir(Configuration config, String domain, String hash) {
        return new File(getDomainDir(config, domain), hash);
    }

    private static File getAliasFile(Configuration config, String domain, File sourceFile) throws IOException {
        String alias = sanitizeAlias(sourceFile.getName());
        return new File(
                new File(getDomainDir(config, domain), "_aliases"),
                alias + ".latest"
        );
    }

    private static File getLowerCaseAliasFile(Configuration config, String domain, File sourceFile) {
        String alias = sanitizeAlias(sourceFile.getName()).toLowerCase(Locale.ROOT);
        return new File(
                new File(getDomainDir(config, domain), "_aliases"),
                alias + ".latest"
        );
    }

    private static File getDomainDir(Configuration config, String domain) {
        return new File(new File(config.getCacheDir()), domain);
    }

    private static void cleanupHashIfUnreferenced(Configuration config, String domain, String hash) throws IOException {
        if (isHashReferencedByAnyAlias(config, domain, hash)) {
            return;
        }
        File newLayout = getHashEntryDir(config, domain, hash);
        if (newLayout.exists()) {
            deleteDirectory(newLayout.toPath());
        }
        File legacyLayout = getLegacyHashEntryDir(config, domain, hash);
        if (legacyLayout.exists()) {
            deleteDirectory(legacyLayout.toPath());
        }
    }

    private static boolean isHashReferencedByAnyAlias(Configuration config, String domain, String hash) throws IOException {
        File aliasDir = new File(getDomainDir(config, domain), "_aliases");
        if (!aliasDir.exists() || !aliasDir.isDirectory()) {
            return false;
        }
        try (Stream<Path> stream = Files.list(aliasDir.toPath())) {
            for (Path aliasFile : (Iterable<Path>) stream::iterator) {
                if (!aliasFile.getFileName().toString().endsWith(".latest")) {
                    continue;
                }
                String mappedHash = new String(Files.readAllBytes(aliasFile), StandardCharsets.UTF_8).trim();
                if (hash.equals(mappedHash)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String sanitizeAlias(String rawName) {
        if (rawName == null || rawName.isEmpty()) {
            return "_unknown";
        }
        return rawName.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
