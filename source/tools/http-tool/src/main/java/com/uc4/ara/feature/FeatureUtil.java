package com.uc4.ara.feature;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 * static methods for log & debug messages.
 * 
 * @author Roger Talkov
 * @version $Rev: 27244 $ $Date: 2014/12/19 $
 */
public class FeatureUtil {

    /**
     * The Constant debug.
     */
    private static final boolean debug;

    /**
     * The Constant logFile.
     */
    private static final PrintWriter logFile;

    /**
     * The Constant traceFile.
     */
    private static final PrintWriter traceFile;

    /**
     * The compiled version.
     */
    private static String compiledVersion = null;

    /**
     * The compiled date.
     */
    private static String compiledDate = null;

    static {
        debug = "true".equalsIgnoreCase(System.getProperty("debug"));
        PrintWriter plog = null;
        PrintWriter ptrace = null;
        try {
            // check for log & trace files in -D options
            String logName = System.getProperty("logFile");
            String traceName = System.getProperty("traceFile");
            if (logName != null)
                plog = new PrintWriter(logName);
            if (traceName != null)
                ptrace = new PrintWriter(logName);
            // close the log & trace files on exit
            Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    try {
                        if (logFile != null)
                            logFile.close();
                        if (traceFile != null)
                            traceFile.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(100);
        }
        logFile = plog;
        traceFile = ptrace;
    } // static

    /**
     * Message types, each type has a prefix that will be prepended on the
     * message sent to logMsg.
     */
    public enum MsgTypes {

        /**
         * The NONE.
         */
        NONE(""),
        /**
         * The INFO.
         */
        INFO("http-tool: INFO: "),
        /**
         * The WARNING.
         */
        WARNING("http-tool: WARNING: "),
        /**
         * The ERROR.
         */
        ERROR("http-tool: ERROR: "),
        /**
         * The EXCEPTION.
         */
        EXCEPTION("http-tool: EXCEPTION: "),
        /**
         * The FAULT_OTHER.
         */
        FAULT_OTHER("http-tool: FAULT_OTHER: "),
        /**
         * The PARAM.
         */
        PARAM("http-tool: PARAM: "),

        GENERAL("http-tool: ");
        /**
         * The prefix.
         */
        private String prefix;

        /**
         * Instantiates a new msg types.
         * 
         * @param prefix
         *            the prefix
         */
        MsgTypes(String prefix) {
            this.prefix = prefix;
        }

        /**
         * Gets the prefix.
         * 
         * @return the prefix
         */
        String getPrefix() {
            return prefix;
        }
    }

    /**
     * Dbg msg.
     * 
     * @param msg
     *            the msg
     */
    public static void dbgMsg(String msg) {
        if (debug) {
            msg = "D- " + msg;
            System.out.println(msg);
            if (traceFile != null)
                traceFile.println(msg);
        }
    }

    /**
     * Checks if is dbg enabled.
     * 
     * @return true if debug enabled
     */
    public static boolean isDbgEnabled() {
        return debug;
    }

    /**
     * Log msg.
     * 
     * @param msg
     *            the msg
     */
    public static void logMsg(String msg) {
        logMsg(msg, MsgTypes.NONE);
    }

    /**
     * write a message to STDOUT and the log file.
     * 
     * @param msg
     *            message text
     * @param type
     *            the type {@link MsgTypes}
     */
    public static void logMsg(String msg, MsgTypes type) {
        msg = type.prefix + msg;
        System.out.println(msg);
        if (logFile != null)
            logFile.println(msg);
        if (traceFile != null)
            traceFile.println(msg);
    }

    /**
     * Log msg.
     * 
     * @param t
     *            the t
     */
    public static void logMsg(Throwable t) {
        logMsg(t.getMessage(), MsgTypes.ERROR);
        if (t.getCause() != null) {
            logMsg(t.getCause().getMessage(), MsgTypes.ERROR);
            logMsg(t.getCause());
        }
        // commented so that stackstraced themselves don't have the logging prefix
        /*for (StackTraceElement stackTraceElement : t.getStackTrace()) {
            logMsg(stackTraceElement.toString(), MsgTypes.ERROR);
        }*/
        t.printStackTrace();
    }

    /**
     * read a text file.
     * 
     * @param file
     *            the file
     * @return the file contents as a String
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     */
    public static String getFileChars(File file) throws IOException {
        return new String(getFileBytes(file));
    }

    /**
     * Gets the file chars.
     * 
     * @param fileName
     *            the file name
     * @return the file chars
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     * @see #getFileChars(File)
     */
    public static String getFileChars(String fileName) throws IOException {
        return getFileChars(new File(fileName));
    }

    /**
     * write a text file.
     * 
     * @param chars
     *            character data
     * @param file
     *            destination
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     */
    public static void writeFile(String chars, File file) throws IOException {
        FileOutputStream fos = new FileOutputStream(file);
        FeatureUtil.logMsg("Writing file " + file.getAbsolutePath() + " using Encoding UTF-8");
        OutputStreamWriter writer = new OutputStreamWriter(fos, "UTF-8");
        BufferedWriter fout = new BufferedWriter(writer);
        fout.write(chars);
        fout.flush();
        fout.close();
    }

    /**
     * Write file.
     * 
     * @param chars
     *            the chars
     * @param fileName
     *            the file name
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     * @see #writeFile(String, File)
     */
    public static void writeFile(String chars, String fileName)
            throws IOException {
        writeFile(chars, new File(fileName));
    }

    /**
     * read the bytes of a file, mostly for reading jar files.
     * 
     * @param file
     *            the file
     * @return the file contents as a byte array
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     */
    public static byte[] getFileBytes(File file) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        BufferedInputStream fin = new BufferedInputStream(new FileInputStream(
                file));
        byte buf[] = new byte[8192];
        int ret = 0;
        while ((ret = fin.read(buf)) != -1) {
            bout.write(buf, 0, ret);
        }
        fin.close();
        return bout.toByteArray();
    }

    /**
     * Gets the bytes of an inputstream.
     * 
     * @param is
     *            the is
     * @return the file bytes
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     */
    public static byte[] getFileBytes(InputStream is) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        BufferedInputStream fin = new BufferedInputStream(is);
        byte buf[] = new byte[8192];
        int ret = 0;
        while ((ret = fin.read(buf)) != -1) {
            bout.write(buf, 0, ret);
        }
        fin.close();
        return bout.toByteArray();
    }

    /**
     * convenience method to create an xml Document.
     * 
     * @param xml
     *            the xml to parse
     * @return Document representing the xml
     * @throws ParserConfigurationException
     *             the parser configuration exception
     * @throws SAXException
     *             the sAX exception
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     */
    public static Document createDocument(String xml)
            throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
        doc.getDocumentElement().normalize();

        return doc;
    }

    /**
     * Creates the document.
     * 
     * @param xmlFile
     *            the xml file
     * @return the document
     * @throws ParserConfigurationException
     *             the parser configuration exception
     * @throws SAXException
     *             the sAX exception
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     * @see #createDocument(String)
     */
    public static Document createDocument(File xmlFile)
            throws ParserConfigurationException, SAXException, IOException {
        return createDocument(getFileChars(xmlFile));
    }

    /**
     * format xml with 2 space indentation.
     * 
     * @param doc
     *            Docment/Node containing the xml
     * @return a formatted String
     * @throws TransformerException
     *             the transformer exception
     * @throws TransformerConfigurationException
     *             the transformer configuration exception
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     */
    public static String xmlToString(Node doc) throws TransformerException,
    TransformerConfigurationException, IOException {
        // format the xml into a String with 2 space indent
        DOMSource domSource = new DOMSource(doc);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(
                "{http://xml.apache.org/xalan}indent-amount", "2");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("encoding", "UTF-8");

        StringWriter sw = new StringWriter();
        StreamResult sr = new StreamResult(sw);
        transformer.transform(domSource, sr);

        // strip out blank lines
        BufferedReader br = new BufferedReader(new StringReader(sw.toString()));
        StringWriter sw1 = new StringWriter();
        PrintWriter bw = new PrintWriter(sw1);
        String line = null;
        while ((line = br.readLine()) != null) {
            if (line.trim().length() > 0)
                bw.println(line);
        }
        return sw1.toString();
    }

    /**
     * Gets the compiled version. This is performed by scanning the manifest.mf
     * files in the current jar and searching for the key
     * <code>Application-Version</code>
     * 
     * @param manifestContentGroup
     *            the manifest content group
     * @return the compiled version
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     */
    public static String getCompiledVersion(String manifestContentGroup)
            throws IOException {

        if (compiledVersion != null)
            return compiledVersion;

        Enumeration<URL> resources = ClassLoader.getSystemClassLoader().getResources("META-INF/MANIFEST.MF");

        compiledVersion = "unknown";
        compiledDate = "unknown";

        while (resources.hasMoreElements()) {
            URL url = resources.nextElement();
            // System.out.println("file: " + url.getFile());
            String u = url.getFile();
            int idx = u.indexOf("!");
            if (idx > 0)
                u = u.substring(0, idx);
            if (u.startsWith("file:"))
                u = u.substring(5);
            try {
                u = u.replace("%20", " ");
                JarFile myJar = new JarFile(u); // various
                // constructors
                // available
                Manifest manifest = myJar.getManifest();
                Map<String, Attributes> manifestContents = manifest
                        .getEntries();
                for (Map.Entry<String, Attributes> entry : manifestContents
                        .entrySet()) {
                    // System.out.println("  key: " + key);
                    Attributes attrs = entry.getValue();
                    for (Map.Entry<Object, Object> entry2 : attrs.entrySet()) {
                        // System.out.println("    k: " + key2 + ", "
                        // + attrs.get(key2));
                        if (entry.getKey().equals(manifestContentGroup) &&
                                entry2.getKey().toString().equals("Application-BuildDate")) {
                            compiledDate = entry2.getValue().toString();
                        }

                        if (entry.getKey().equals(manifestContentGroup)
                                && entry2.getKey().toString().equals("Application-Version")) {
                            compiledVersion = entry2.getValue().toString();
                        }
                    }
                }
            } catch (IOException e) {
                FeatureUtil.logMsg(e);
            }
        }

        return compiledVersion;
    }

    /**
     * Gets the compiled date.
     * 
     * @param manifestContentGroup
     *            the manifest content group
     * @return the compiled date
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     */
    public static String getCompiledDate(String manifestContentGroup)
            throws IOException {
        if (compiledDate == null)
            getCompiledVersion(manifestContentGroup);
        return compiledDate;
    }

    /**
     * Repeats the character c count times and returns the result.
     * 
     * @param c
     *            the character to repeat
     * @param count
     *            the number of times the character should be repeated.
     * 
     * @return the resulting string
     */
    public static String repeat(char c, int count) {
        char[] ret = new char[count];
        Arrays.fill(ret, c);
        return new String(ret);
        // StringBuffer ret = new StringBuffer();
        // for (int i = 0; i < count; ++i)
        // ret.append(c);
        // return ret.toString();
    }

    public static void printGeneralHelp(String basePackage) throws Exception {
        Package pkg = Package.getPackage(basePackage);
        List<String> packageNames = new ArrayList<String>();

        FeatureUtil.logMsg("Available Method Groups:");
        FeatureUtil.logMsg("=========================");

        if(pkg != null)
        {
            for(String subPackage : getPackageNamesInPackage(basePackage)) {
                Set<Class> classes = getClassesInPackage(basePackage, subPackage.replace(basePackage + ".", ""));
                for(Class clazz : classes) {
                    if(AbstractPublicFeature.class.isAssignableFrom(clazz) && !clazz.getSimpleName().equals(AbstractPublicFeature.class.getSimpleName())) {
                        if(!AbstractInternalFeature.class.isAssignableFrom(clazz) && !packageNames.contains(subPackage.replace(basePackage + ".", ""))) {
                            packageNames.add(subPackage.replace(basePackage + ".", ""));
                        }
                    }
                }
            }
        }

        for(String packageName : packageNames) {
            FeatureUtil.logMsg(packageName);
        }
    }

    public static void printPackageHelp(String basePackage, String packageName) throws Exception {
        Package pkg = Package.getPackage(basePackage);

        FeatureUtil.logMsg("Available Package Methods:");
        FeatureUtil.logMsg("===========================");

        if(pkg != null)
        {
            Set<Class> classes = getClassesInPackage(basePackage, packageName);
            for(Class clazz : classes) {
                if(AbstractPublicFeature.class.isAssignableFrom(clazz) && !clazz.getSimpleName().equals(AbstractPublicFeature.class.getSimpleName())) {
                    if(!AbstractInternalFeature.class.isAssignableFrom(clazz)) {
                        if(!Modifier.isAbstract(clazz.getModifiers()))
                        {
                            IFeature feature = (IFeature) clazz.newInstance();
                            feature.initialize();
                            FeatureUtil.logMsg(feature.getClass().getSimpleName());
                            feature.printDescription(true);
                        }
                    }
                }
            }
        }
    }

    public static boolean packageExists(String basePackage, String packageName) {
        Package pkg = Package.getPackage(String.format(basePackage, ".", packageName));
        if(pkg != null)
            return true;

        return false;
    }

    private static Set<String> getPackageNamesInPackage(String packageName) {
        Set<String> packageNames = new HashSet<String>();
        String packageNameSlashed = packageName.replace(".", "/");
        // Get a File object for the package
        URL directoryURL = Thread.currentThread().getContextClassLoader().getResource(packageNameSlashed);
        if (directoryURL == null) {
            FeatureUtil.logMsg("Could not retrieve URL resource: " + packageNameSlashed);
            return packageNames;
        }

        JarFile jar;
        try {
            jar = new JarFile(URLDecoder.decode(FeatureUtil.class.getProtectionDomain().getCodeSource().getLocation().getPath()));

            // Getting the files into the jar
            Enumeration<? extends JarEntry> enumeration = jar.entries();

            // Iterates into the files in the jar file
            while (enumeration.hasMoreElements()) {
                ZipEntry zipEntry = enumeration.nextElement();

                if(zipEntry.getName().startsWith(packageNameSlashed))
                {
                    // Is this a class?
                    if (zipEntry.getName().endsWith("/") && !zipEntry.getName().equals(packageNameSlashed + "/")) {

                        // Relative path of file into the jar.
                        String className = zipEntry.getName();
                        // Complete class name
                        className = className.replace(".class", "").replace("/", ".");
                        // Load class definition from JVM
                        String resultPackageName = className.replace(packageName + ".", "");
                        resultPackageName = resultPackageName.trim().substring(0, resultPackageName.trim().length() - 1);
                        if(!packageNames.contains(resultPackageName))
                            packageNames.add(resultPackageName);
                    }
                }
            }
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return packageNames;
    }

    private static Set<Class> getClassesInPackage(String packageName, String subPackageName) {
        Set<Class> classes = new HashSet<Class>();
        String packageNameSlashed = packageName.replace(".", "/");
        // Get a File object for the package
        URL directoryURL = Thread.currentThread().getContextClassLoader().getResource(packageNameSlashed);
        if (directoryURL == null) {
            FeatureUtil.logMsg("Could not retrieve URL resource: " + packageNameSlashed);
            return classes;
        }

        String directoryString = directoryURL.getFile();
        if (directoryString == null) {
            FeatureUtil.logMsg("Could not find directory for URL resource: " + packageNameSlashed);
            return classes;
        }
        JarFile jar;
        try {
            jar = new JarFile(URLDecoder.decode(FeatureUtil.class.getProtectionDomain().getCodeSource().getLocation().getPath()));
            // Getting the files into the jar
            Enumeration<? extends JarEntry> enumeration = jar.entries();

            // Iterates into the files in the jar file
            while (enumeration.hasMoreElements()) {
                ZipEntry zipEntry = enumeration.nextElement();

                if(zipEntry.getName().startsWith(packageNameSlashed + "/" + subPackageName))
                {
                    // Is this a class?
                    if (zipEntry.getName().endsWith(".class")) {

                        // Relative path of file into the jar.
                        String className = zipEntry.getName();

                        // Complete class name
                        className = className.replace(".class", "").replace("/", ".");

                        // Load class definition from JVM
                        Class<?> clazz = FeatureUtil.class.getClassLoader().loadClass(className);

                        classes.add(clazz);
                    }
                }
            }
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return classes;
    }
}
