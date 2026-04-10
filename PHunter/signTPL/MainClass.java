package signTPL;

import analyze.*;
import org.apache.commons.cli.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import symbolicExec.MethodDigest;

import java.io.File;
import java.io.IOException;

import static util.AARUtils.aarToJar;

public class MainClass {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    protected final Options options = new Options();
    protected CommandLine cmd = null;

    private static final String OPTION_APK_FILE = "targetAPK";
    private static final String OPTION_PRE_BINARY = "preTPL";
    private static final String OPTION_POST_BINARY = "postTPL";
    private static final String OPTION_PATCH_FILE = "patchFiles";
    private static final String OPTION_THREAD_NUMBER = "threadNum";
    //    private static final String OPTION_OUTPUT_FILE = "output";
    private static final String OPTION_ANDROID_JAR = "androidJar";
    private static final String OPTION_ENABLE_DEBUG = "enableDebug";
    private static final String OPTION_CACHE_DIR = "cacheDir";
    private static final String OPTION_CACHE_MODE = "cacheMode";
    private static final String OPTION_PREWARM_ONLY = "prewarmOnly";
    private static final String OPTION_PREWARM_APK_ONLY = "prewarmAPKOnly";

    protected MainClass() {
        initializeCommandLineOptions();
    }

    /**
     * Initializes the set of available command-line options
     */
    private void initializeCommandLineOptions() {
        options.addOption("?", "help", false, "Print this help message");
        options.addOption(OPTION_APK_FILE, true, "Path to pre-patched binary(.apk), " +
                "or a directory contains multi apks");
        options.addOption(OPTION_PRE_BINARY, true, "Path to pre-patched binary(.jar/.aar)");
        options.addOption(OPTION_POST_BINARY, true, "Path to post-patched binary(.jar/.aar)");
        options.addOption(OPTION_PATCH_FILE, true, "Path to patch files, " +
                "if exist more than 1 files, split by the ';’ (e.g., 1.diff;2.diff)");
//        options.addOption(OPTION_OUTPUT_FILE, true, "path to output, if have multi apks," +
//                " the path should be a directory, each of apk will have a res file in the dir");
        options.addOption(OPTION_THREAD_NUMBER, true, "The number of threads to use");
        options.addOption(OPTION_ANDROID_JAR, true, "The path to android.jar");
        options.addOption(OPTION_ENABLE_DEBUG, false, "Is enable debug level");
        options.addOption(OPTION_CACHE_DIR, true, "Cache root directory for Soot jimple artifacts");
        options.addOption(OPTION_CACHE_MODE, true, "Cache mode: off|readonly|readwrite");
        options.addOption(OPTION_PREWARM_ONLY, false, "Only prewarm TPL (pre/post binaries) cache then exit");
        options.addOption(OPTION_PREWARM_APK_ONLY, false, "Only prewarm APK cache then exit");
    }

    public static void main(String[] args) throws Exception {
//        // Keep Soot typing diagnostics at default logger levels.
//        System.setProperty("org.slf4j.simpleLogger.log.soot.jimple.toolkits.typing.fast.TypePromotionUseVisitor", "off");
        // Codex modification: suppress noisy Soot typing diagnostics so terminal output stays close to the legacy PHunter style.
        System.setProperty("org.slf4j.simpleLogger.log.soot.jimple.toolkits.typing.fast.TypePromotionUseVisitor", "off");
//        TimeRecorder.beforeTotal = System.currentTimeMillis();
        MainClass main = new MainClass();
        main.run(args);
//        TimeRecorder.afterTotal = System.currentTimeMillis();
    }

    protected void run(String[] args) throws Exception {
        HelpFormatter hf = new HelpFormatter();
        hf.setWidth(110);

        // We need proper parameters
        final HelpFormatter formatter = new HelpFormatter();
        if (args.length == 0) {
            hf.printHelp("help", options, true);
            System.exit(0);
        }

        // Parse the command-line parameters
        try {
            CommandLineParser parser = new PosixParser();
            cmd = parser.parse(options, args);
            cmd.getArgs();

            // Do we need to display the user manual?
            if (cmd.hasOption("?") || cmd.hasOption("help")) {
                formatter.printHelp("signTPL [OPTIONS]", options);
                return;
            }

            Configuration config = new Configuration();
            boolean prewarmOnly = cmd.hasOption(OPTION_PREWARM_ONLY);
            boolean prewarmAPKOnly = cmd.hasOption(OPTION_PREWARM_APK_ONLY);
            if (prewarmOnly && prewarmAPKOnly) {
                throw abort("Options --prewarmOnly and --prewarmAPKOnly cannot be used together");
            }
            parseCommandOptions(
                    cmd,
                    config,
                    !prewarmOnly,
                    !prewarmAPKOnly,
                    !prewarmOnly && !prewarmAPKOnly
            );

            if (prewarmAPKOnly) {
                TimeRecorder.beforeAPK = System.currentTimeMillis();
                new APKAnalyzer(config);
                TimeRecorder.afterAPK = System.currentTimeMillis();
                logger.info("APK cache prewarm completed.");
                return;
            }

            // 1 analyze the pre-patch and post-patch binary
            TimeRecorder.beforePre = System.currentTimeMillis();
            BinaryAnalyzer pre = new BinaryAnalyzer(config, true);
            TimeRecorder.afterPre = System.currentTimeMillis();

            TimeRecorder.beforePost = System.currentTimeMillis();
            BinaryAnalyzer post = new BinaryAnalyzer(config, false);
            TimeRecorder.afterPost = System.currentTimeMillis();

            if (prewarmOnly) {
                logger.info("TPL cache prewarm completed.");
                return;
            }

//            // 2 analyze the patch to extract patch-related method for location
            PatchSummary patchSummary = new PatchSummary(config, pre, post);

//             3 analyze the target obfuscated app(maybe more than one)

            TimeRecorder.beforeAPK = System.currentTimeMillis();
            APKAnalyzer apk = new APKAnalyzer(config);
            TimeRecorder.afterAPK = System.currentTimeMillis();

            PatchPresentTest_new ppt = new PatchPresentTest_new(config, patchSummary, apk);


        } catch (AbortAnalysisException e) {
            // Silently return
        } catch (ParseException e) {
            System.err.printf("Failed to parse command-line arguments: %s%n", e.getMessage());
            formatter.printHelp("signTPL [OPTIONS]", options);
        } catch (Exception e) {
            System.err.printf("The analysis has failed. Error message: %s\n", e.getMessage());
            e.printStackTrace();
        }
    }


    protected void DataflowAnalysisDebug(Analyzer pre, Analyzer post, String className, String methodName) {
        MethodDigest preD = null, postD = null;
        for (ClassAttr clazz : pre.allClasses.values())
            if (clazz.name.contains(className)) {
                for (MethodAttr method : clazz.methods) {
                    if (method.body.getMethod().getName().equals(methodName)) {
                        preD = new MethodDigest(method.body, null);
                        int a = 0;
                    }
                }
                if (preD != null)
                    break;
            }
        for (ClassAttr clazz : post.allClasses.values())
            if (clazz.name.endsWith(className)) {
                for (MethodAttr method : clazz.methods) {
                    if (method.body.getMethod().getName().equals(methodName)) {
                        postD = new MethodDigest(method.body, null);
                        break;
                    }
                }
                if (postD != null)
                    break;
            }
    }

    protected void parseCommandOptions(
            CommandLine cmd,
            Configuration config,
            boolean requireAPK,
            boolean requireTPL,
            boolean requirePatch
    ) throws IOException {
        String apkFile = cmd.getOptionValue(OPTION_APK_FILE);
        if (requireAPK) {
            apkFile = getRequiredOptionValue(cmd, OPTION_APK_FILE);
        }
        if (apkFile != null && !apkFile.trim().isEmpty()) {
            apkFile = resolveExistingPath(apkFile.trim(), OPTION_APK_FILE, true);
            config.setTargetAPKFile(apkFile);
        }

        String preBinary = cmd.getOptionValue(OPTION_PRE_BINARY);
        if (requireTPL) {
            preBinary = getRequiredOptionValue(cmd, OPTION_PRE_BINARY);
        }
        if (preBinary != null && !preBinary.trim().isEmpty()) {
            preBinary = resolveExistingPath(preBinary.trim(), OPTION_PRE_BINARY, false);
            if (preBinary.endsWith(".aar")) {
                logger.info(String.format("Convert pre-patched binary %s to %s",
                        preBinary, preBinary.replace(".aar", ".jar")));
                preBinary = aarToJar(preBinary);
            }
            config.setPreBinary(preBinary);
        }

        String postBinary = cmd.getOptionValue(OPTION_POST_BINARY);
        if (requireTPL) {
            postBinary = getRequiredOptionValue(cmd, OPTION_POST_BINARY);
        }
        if (postBinary != null && !postBinary.trim().isEmpty()) {
            postBinary = resolveExistingPath(postBinary.trim(), OPTION_POST_BINARY, false);
            if (postBinary.endsWith(".aar")) {
                logger.info(String.format("Convert post-patched binary %s to %s",
                        postBinary, postBinary.replace(".aar", ".jar")));
                postBinary = aarToJar(postBinary);
            }
            config.setPostBinary(postBinary);
        }

        String androidJAR = getRequiredOptionValue(cmd, OPTION_ANDROID_JAR);
        androidJAR = resolveExistingPath(androidJAR, OPTION_ANDROID_JAR, false);
        config.setAndroidPlatformJar(androidJAR);

        String threadNumber = cmd.getOptionValue(OPTION_THREAD_NUMBER);
        if (threadNumber != null && !threadNumber.trim().isEmpty()) {
            try {
                int threadNumValue = Integer.parseInt(threadNumber.trim());
                if (threadNumValue <= 0) {
                    throw new NumberFormatException("must be greater than 0");
                }
            } catch (NumberFormatException ex) {
                throw abort(String.format("Invalid --%s value '%s', expected a positive integer",
                        OPTION_THREAD_NUMBER, threadNumber));
            }
            config.setThreadNumber(threadNumber);
        }

        String patch = cmd.getOptionValue(OPTION_PATCH_FILE);
        if (requirePatch) {
            patch = getRequiredOptionValue(cmd, OPTION_PATCH_FILE);
        }
        if (patch != null && !patch.trim().isEmpty()) {
            String[] patchFiles = patch.split(";");
            for (int i = 0; i < patchFiles.length; i++) {
                patchFiles[i] = resolveExistingPath(patchFiles[i], OPTION_PATCH_FILE, false);
            }
            config.setPatchFiles(String.join(";", patchFiles));
        }

        if (cmd.hasOption(OPTION_ENABLE_DEBUG)) {
            String debug = cmd.getOptionValue(OPTION_ENABLE_DEBUG);
            if (debug != null)
                config.setEnableDebugLevel(Boolean.parseBoolean(debug));
        } else {
//            config.setEnableDebugLevel(true); // default do not enable debug level
            // Codex modification: keep debug output disabled by default to avoid verbose terminal noise.
            config.setEnableDebugLevel(false);
        }

        String cacheDir = cmd.getOptionValue(OPTION_CACHE_DIR);
        if (cacheDir != null && !cacheDir.trim().isEmpty()) {
            File cacheRoot = new File(cacheDir.trim());
            if (!cacheRoot.exists() && !cacheRoot.mkdirs()) {
                throw abort("Failed to create cache directory: " + cacheDir);
            }
            config.setCacheDir(cacheRoot.getAbsolutePath());
        }
        String cacheMode = cmd.getOptionValue(OPTION_CACHE_MODE);
        if (cacheMode != null && !cacheMode.trim().isEmpty()) {
            config.setCacheMode(cacheMode.trim());
        }
    }

    private String getRequiredOptionValue(CommandLine cmd, String optionName) {
        String value = cmd.getOptionValue(optionName);
        if (value == null || value.trim().isEmpty()) {
            throw abort(String.format("Missing required option --%s", optionName));
        }
        return value.trim();
    }

    private String resolveExistingPath(String rawPath, String optionName, boolean allowDirectory) throws IOException {
        String resolved = tryCommonPathFix(rawPath);
        File file = new File(resolved);
        if (!file.exists()) {
            throw abort(String.format("Path for --%s does not exist: %s", optionName, rawPath));
        }
        if (!allowDirectory && file.isDirectory()) {
            throw abort(String.format("Path for --%s must be a file, but got directory: %s", optionName, rawPath));
        }
//        return file.getCanonicalPath();
        // Codex modification: preserve the user-supplied relative path in logs to match legacy PHunter output style.
        return resolved;
    }

    private String tryCommonPathFix(String rawPath) {
        File original = new File(rawPath);
        if (original.exists()) {
            return rawPath;
        }
        String[] candidates = new String[]{
                rawPath.replace("real_sample", "real-sample"),
                rawPath.replace("real-sample", "real_sample")
        };
        for (String candidate : candidates) {
            if (!candidate.equals(rawPath) && new File(candidate).exists()) {
                logger.warn("Path {} does not exist, using {} instead.", rawPath, candidate);
                return candidate;
            }
        }
        return rawPath;
    }

    private AbortAnalysisException abort(String message) {
        System.err.println(message);
        return new AbortAnalysisException();
    }
}
