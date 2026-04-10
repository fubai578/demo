package analyze;

import org.slf4j.Logger;
import symbolicExec.MethodDigest;

import javax.script.ScriptEngineManager;
import java.io.*;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class AnalyzerCacheSupport {
    private static final String PAYLOAD_FILE = "analyzer.bin";

    private AnalyzerCacheSupport() {
    }

    public static Map<String, ClassAttr> tryLoadAnalyzer(
            Configuration config,
            String domain,
            File sourceFile,
            Logger logger
    ) {
        if (!SootCacheSupport.isCacheEnabled(config) || sourceFile == null) {
            return null;
        }
        try {
            File directEntry = SootCacheSupport.getEntryDir(config, domain, sourceFile);
            Map<String, ClassAttr> loaded = loadFromEntry(directEntry);
            if (loaded != null) {
                logger.info("Using cached {} analysis for {}", domain, sourceFile.getAbsolutePath());
                return loaded;
            }

            File aliasEntry = getAliasEntryDirIfReady(config, domain, sourceFile);
            if (aliasEntry != null) {
                loaded = loadFromEntry(aliasEntry);
                if (loaded != null) {
                    logger.info("Using alias-mapped {} analysis cache for {}", domain, sourceFile.getName());
                    return loaded;
                }
            }
        } catch (Exception ex) {
            logger.warn("Failed to load {} analysis cache: {}", domain, ex.toString(), ex);
        }
        return null;
    }

    public static void storeAnalyzer(
            Configuration config,
            String domain,
            File sourceFile,
            Map<String, ClassAttr> allClasses,
            Logger logger
    ) {
        if (!SootCacheSupport.isCacheEnabled(config)
                || !SootCacheSupport.isReadWrite(config)
                || sourceFile == null
                || allClasses == null) {
            return;
        }
        try {
            prepareAnalyzerForSerialization(allClasses);

            File entryDir = SootCacheSupport.getEntryDir(config, domain, sourceFile);
            if (!entryDir.exists() && !entryDir.mkdirs()) {
                throw new IOException("Failed to create analysis cache entry dir: " + entryDir.getAbsolutePath());
            }
            File payloadFile = getPayloadFile(entryDir);
            try (ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(payloadFile)))) {
                oos.writeObject(allClasses);
            }

            SootCacheSupport.markReady(
                    entryDir,
                    "source=" + sourceFile.getCanonicalPath() + "\n"
                            + "name=" + sourceFile.getName() + "\n"
                            + "size=" + sourceFile.length() + "\n"
                            + "mtime=" + sourceFile.lastModified() + "\n"
            );
            registerAlias(config, domain, sourceFile, entryDir);
        } catch (Exception ex) {
            logger.warn("Failed to store {} analysis cache for {}: {}", domain, sourceFile.getAbsolutePath(),
                    ex.toString(), ex);
        }
    }

    private static Map<String, ClassAttr> loadFromEntry(File entryDir) throws IOException, ClassNotFoundException {
        if (!isReady(entryDir)) {
            return null;
        }
        File payload = getPayloadFile(entryDir);
        try (ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(payload)))) {
            Object obj = ois.readObject();
            if (!(obj instanceof Map)) {
                return null;
            }
            return (Map<String, ClassAttr>) obj;
        }
    }

    private static boolean isReady(File entryDir) {
        if (entryDir == null) {
            return false;
        }
        return SootCacheSupport.getReadyFile(entryDir).exists() && getPayloadFile(entryDir).exists();
    }

    private static File getPayloadFile(File entryDir) {
        return new File(entryDir, PAYLOAD_FILE);
    }

    private static void prepareAnalyzerForSerialization(Map<String, ClassAttr> allClasses) {
        ensureDigestScriptEngines();
        Set<MethodAttr> visitedMethods = new HashSet<>();
        for (ClassAttr clazz : allClasses.values()) {
            for (MethodAttr method : clazz.methods) {
                if (!visitedMethods.add(method)) {
                    continue;
                }
                if (method.hasBody && method.digest == null && method.body != null) {
                    method.digest = new MethodDigest(method.body, null);
                }
                if (method.digest != null) {
                    method.digest.prepareForSerialization();
                }
            }
        }
    }

    private static void ensureDigestScriptEngines() {
        if (PatchPresentTest_new.sePy != null && PatchPresentTest_new.seJs != null) {
            return;
        }
        ScriptEngineManager manager = new ScriptEngineManager();
        if (PatchPresentTest_new.sePy == null) {
            PatchPresentTest_new.sePy = manager.getEngineByName("python");
        }
        if (PatchPresentTest_new.seJs == null) {
            PatchPresentTest_new.seJs = manager.getEngineByName("JavaScript");
        }
    }

    private static File getAliasEntryDirIfReady(Configuration config, String domain, File sourceFile) throws IOException {
        String hash = SootCacheSupport.readAliasHash(config, domain, sourceFile);
        if (hash.isEmpty()) {
            return null;
        }
        File entryDir = SootCacheSupport.resolveEntryDirByHash(config, domain, hash);
        return isReady(entryDir) ? entryDir : null;
    }

    private static void registerAlias(Configuration config, String domain, File sourceFile, File entryDir) throws IOException {
        SootCacheSupport.registerAlias(config, domain, sourceFile, entryDir);
    }
}
