package analyze;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Main;
import soot.PackManager;
import soot.Transform;
import soot.options.Options;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class APKAnalyzer extends Analyzer {
    private final Configuration config;
    private final Logger logger = LoggerFactory.getLogger(getClass());


    public APKAnalyzer(Configuration config) throws IOException {
        super(config);
        this.config = config;
        File inputFile = new File(config.getTargetAPKFile());
        Map<String, ClassAttr> cachedClasses = AnalyzerCacheSupport.tryLoadAnalyzer(
                config, "apk_analysis", inputFile, logger);
        if (cachedClasses != null) {
            this.allClasses = cachedClasses;
            rebuildAllMethodsFromClasses();
            return;
        }

        SootCallGraph cg = analyze();
        buildCG(cg);
        AnalyzerCacheSupport.storeAnalyzer(config, "apk_analysis", inputFile, this.allClasses, logger);
    }

    private void initializeSoot(boolean useCachedCache) {
        soot.G.reset();
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true); //get ICFG
        Options.v().set_no_bodies_for_excluded(true);

        if (useCachedCache) {
            Options.v().set_src_prec(Options.src_prec_only_class);
            Options.v().set_output_format(Options.output_format_n);
            return;
        }

        // Read (APK Dex-to-Jimple) Options
        Options.v().set_force_android_jar(config.getAndroidPlatformJar()); // The path to Android Platforms
        Options.v().set_src_prec(Options.src_prec_apk); // Determine the input is an APK
//        Options.v().set_process_multiple_dex(true);  // Inform Dexpler that the APK may have more than one .dex files
        // Codex modification: Soot 4.7.x removed set_process_multiple_dex; search dex files inside APK archives instead.
        Options.v().set_search_dex_in_archives(true);
        Options.v().set_keep_line_number(false);  //do not record linenumber
        Options.v().set_keep_offset(false); // do not keep offset
        Options.v().set_throw_analysis(Options.throw_analysis_dalvik);
        Options.v().set_ignore_resolution_errors(true);
//        Options.v().set_process_dir(Collections.singletonList(config.getTargetAPKFile()));

//        Options.v().setPhaseOption("cg.spark", "on");


        // Write (APK Generation) Options
//        Options.v().set_output_format(Options.output_format_J);
        Options.v().set_output_format(Options.output_format_n);
//        Options.v().set_output_format(Options.output_format_c);
//        Options.v().set_output_format(Options.output_format_dex);
//        Scene.v().loadNecessaryClasses();

        // Resolve required classes
//        Scene.v().addBasicClass("java.io.PrintStream", SootClass.SIGNATURES);
//        Scene.v().addBasicClass("java.lang.System", SootClass.SIGNATURES);
//        Scene.v().loadNecessaryClasses();
    }

    private SootCallGraph analyze() throws IOException {
        File inputFile = new File(config.getTargetAPKFile());
        File cacheEntry = null;
        boolean useCachedCache = false;
        boolean enableSootArtifactCache = SootCacheSupport.isCacheEnabled(config) && !config.isAnalysisCacheOnly();
        if (enableSootArtifactCache) {
            cacheEntry = SootCacheSupport.getEntryDir(config, "apk", inputFile);
            if (SootCacheSupport.isReady(cacheEntry)) {
                useCachedCache = true;
                logger.info("Using cached APK Soot artifacts for {}", config.getTargetAPKFile());
            } else {
                File aliasEntry = SootCacheSupport.getAliasEntryDirIfReady(config, "apk", inputFile);
                if (aliasEntry != null) {
                    cacheEntry = aliasEntry;
                    useCachedCache = true;
                    logger.info("Using alias-mapped APK cache for {}", inputFile.getName());
                }
            }
        }

        if (useCachedCache) {
            try {
                return analyzeOnce(inputFile, cacheEntry, true);
            } catch (RuntimeException ex) {
                logger.warn("Cached APK artifacts failed ({}), fallback to raw APK analysis.",
                        ex.getMessage());
                invalidateCacheEntry(cacheEntry);
            }
        }
        return analyzeOnce(inputFile, cacheEntry, false);
    }

    private SootCallGraph analyzeOnce(File inputFile, File cacheEntry, boolean useCachedCache) throws IOException {
        initializeSoot(useCachedCache);
        SootCallGraph cg = new SootCallGraph(true);
        PackManager.v().getPack("jtp").add(new Transform("jtp.apk", new CallGraphTransform(cg)));
        logger.info(String.format("Analyzing the apk %s", config.getTargetAPKFile()));

        List<String> sootArgs = new ArrayList<>();
        sootArgs.add("-process-dir");
        if (useCachedCache) {
            sootArgs.add(SootCacheSupport.getJimpleDir(cacheEntry).getCanonicalPath());
        } else {
            sootArgs.add(inputFile.getCanonicalPath());
            if (cacheEntry != null && SootCacheSupport.isReadWrite(config)) {
                SootCacheSupport.prepareJimpleOutputDir(cacheEntry);
                Options.v().set_output_format(Options.output_format_class);
                Options.v().set_output_dir(SootCacheSupport.getJimpleDir(cacheEntry).getCanonicalPath());
            }
        }

        try {
            Main.v().run(sootArgs.toArray(new String[0]));
        } catch (RuntimeException ex) {
            if (!useCachedCache && isKnownDexAnnotationBug(ex)) {
                logger.warn("Soot failed on malformed APK annotation ({}). " +
                                "Continue with an empty APK call graph for {}.",
                        ex.getMessage(), config.getTargetAPKFile());
                return cg;
            }
            throw ex;
        }

        if (!useCachedCache && cacheEntry != null && SootCacheSupport.isReadWrite(config)) {
            SootCacheSupport.markReady(
                    cacheEntry,
                    "source=" + inputFile.getCanonicalPath() + "\n"
                            + "name=" + inputFile.getName() + "\n"
                            + "size=" + inputFile.length() + "\n"
                            + "mtime=" + inputFile.lastModified() + "\n"
            );
            SootCacheSupport.registerAlias(config, "apk", inputFile, cacheEntry);
        }
        cg.buildSootCallGraph();
        return cg;
    }

    private void invalidateCacheEntry(File cacheEntry) {
        if (cacheEntry == null) {
            return;
        }
        try {
            SootCacheSupport.deleteDirectory(SootCacheSupport.getJimpleDir(cacheEntry).toPath());
        } catch (IOException ignored) {
        }
        File ready = SootCacheSupport.getReadyFile(cacheEntry);
        if (ready.exists()) {
            ready.delete();
        }
    }

    private boolean isKnownDexAnnotationBug(Throwable ex) {
        Throwable current = ex;
        while (current != null) {
            String message = current.getMessage();
            if (message != null
                    && message.contains("expected 1 element for annotation Deprecated. Got")) {
                return true;
            }
            for (StackTraceElement element : current.getStackTrace()) {
                if ("soot.dexpler.DexAnnotation".equals(element.getClassName())
                        && "addAnnotation".equals(element.getMethodName())) {
                    return true;
                }
            }
            current = current.getCause();
        }
        return false;
    }

    public String getAPKName() {
        return config.getTargetAPKFile();
    }
}
