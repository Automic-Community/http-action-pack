/*
 * (c) 2012 Michael Schwartz e.U.
 * All Rights Reserved.
 * 
 * This program is not a free software. The owner of the copyright
 * can license the software for you. You may not use this file except in
 * compliance with the License. In case of questions please
 * do not hesitate to contact us at idx@mschwartz.eu.
 * 
 * Filename: FileUtil.java
 * Created: 30.05.2012
 * 
 * Author: $LastChangedBy$
 * Date: $LastChangedDate$
 * Revision: $LastChangedRevision$
 */
package com.uc4.ara.feature.utils;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.FileAlreadyExistsException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;

import com.uc4.ara.feature.FeatureUtil;
import com.uc4.ara.feature.FeatureUtil.MsgTypes;

/**
 * Utility class for file-handling.
 */
public class FileUtil {

	/**
	 * The Constant maxBlockSize is the maximum size of one block which will be
	 * allocated to copy a file.
	 */
	public static final int maxBlockSize = 10 * 1024 * 1024;

	private static final int defaultBlockSize = 8 * 1024;

	private static final char[] HEXES = "0123456789ABCDEF".toCharArray();
	
    public static final char EXTENSION_SEPARATOR = '.';
	
	private static final String FILENAME_SPLITTER = "=::=";
	
    /**
     * The extension separator String.
     */
    public static final String EXTENSION_SEPARATOR_STR = Character.toString(EXTENSION_SEPARATOR);

    /**
     * The Unix separator character.
     */
    private static final char UNIX_SEPARATOR = '/';

    /**
     * The Windows separator character.
     */
    private static final char WINDOWS_SEPARATOR = '\\';

	/**
	 * reads the whole content of a file denoted by the parameter
	 * <code>file</code> as byte array.
	 * 
	 * @param file
	 *            the file
	 * @return the byte[]
	 */
	public static byte[] fileAsByteArray(File file) {
		byte[] content = new byte[(int) file.length()];
		RandomAccessFile in = null;
		try {
			in = new RandomAccessFile(file, "r");
			int read = 0;
			do {
				int offset = 0;
				read = in.read(content, offset, content.length - offset);
				offset += read;
			} while (read != -1);
		} catch (IOException e) {
			return null;
		} finally {
			if (in != null)
				try {
					in.close();
				} catch (IOException e) {
					return null;
				}
		}
		return content;
	}

	/**
	 * reads the whole content of a file
	 * as byte array.
	 * 
	 * @param snap
	 *            the archive file [snap.zip]
	 * @param relativePath
	 *            the relative path of the file in archive file
	 * @return the byte[]
	 */
	public static byte[] fileAsByteArray(File snap, String relativePath)
			throws Exception {
		ZipInputStream zin = new ZipInputStream(new FileInputStream(snap));
		ZipEntry entry;
		byte[] b = null;
		String path = relativePath.replaceAll("\\\\", "/");
		while ((entry = zin.getNextEntry()) != null) {

			String entryName = entry.getName().replaceAll("\\\\", "/");

			if (entryName.equals(path)) {

				ByteArrayOutputStream output = new ByteArrayOutputStream();

				byte[] buffer = new byte[defaultBlockSize];

				int read;
				while (-1 != (read = zin.read(buffer))) {
					output.write(buffer, 0, read);
				}

				output.close();

				b = output.toByteArray();

				break;

			}

			zin.closeEntry();

		}

		zin.close();

		return b;
	}
	/**
	 * reads the whole content of a file and returns it as a list of lines.
	 * 
	 * @param file
	 *            the file
	 * @param charset
	 *            the charset
	 * @return the list
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static List<String> fileAsLines(File file, String charset)
			throws IOException {
		List<String> lines = new LinkedList<String>();

		BufferedReader fis = new BufferedReader(new InputStreamReader(
				new FileInputStream(file), charset));

		while (true) {
			String line = fis.readLine();
			if (line == null)
				break;
			lines.add(line);
		}
		fis.close();

		return lines;
	}

	public static List<String> fileAsLines(InputStream is, String charset)
			throws Exception {
		List<String> lines = new LinkedList<String>();

		BufferedReader fis = new BufferedReader(new InputStreamReader(is,
				charset));

		while (true) {
			String line = fis.readLine();
			if (line == null)
				break;
			lines.add(line);
		}
		fis.close();

		return lines;
	}

	/**
	 * reads a File as one single string.
	 * 
	 * @param file
	 *            the file
	 * @return the string
	 */
	public static String fileAsString(File file) {
		byte[] content = fileAsByteArray(file);
		if (content == null)
			return "";
		return new String(content);
	}

	/**
	 * Deletes a directory and its files recursively.
	 * 
	 * @param path
	 *            the path
	 * @return true, if successful
	 */
	public static boolean deleteDirectory(File path) {
		File[] files = path.listFiles();
		for (File file : files) {
			try {
				if (file.isDirectory()) {
					// System.out.println("  delete dir " +
					// file.getCanonicalPath());
					boolean ok = deleteDirectory(file);
					if (!ok) {
						System.out.println("  ups, " + file.getCanonicalPath()
								+ " cannot be deleted");
					}
				} else {
					// System.out.println("  delete file " +
					// file.getCanonicalPath());
					boolean ok = file.delete();
					if (!ok) {
						System.out.println("  ups, " + file.getCanonicalPath()
								+ " cannot be deleted");
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return (path.delete());
	}

	/**Check if child is a sub directory of base
	 * @param base
	 * @param child
	 * @return
	 * @throws IOException
	 */
	public boolean isSubDirectory(File base, File child) throws IOException {
		base = base.getCanonicalFile();
		child = child.getCanonicalFile();

		File parentFile = child;
		while (parentFile != null) {
			if (base.equals(parentFile)) {
				return true;
			}
			parentFile = parentFile.getParentFile();
		}
		return false;
	}

	/**
	 * Writes the content of the string <code>fileContent</code> to a file.
	 * 
	 * @param fileName
	 *            the file name
	 * @param fileContent
	 *            the file content
	 * @throws Exception
	 *             the exception
	 */
	public static void writeFile(String fileName, String fileContent)
			throws Exception {
		File file = new File(fileName);
		FileWriter writer = new FileWriter(file);
		writer.write(fileContent);
		writer.close();
	}

	/**
	 * Writes the content of
	 * <code>content</content> to a file denoted by <code>fileName</code>. The
	 * file will be created with the extension ".filepart", the content will be
	 * stored into the file and then the file will be renamed to the desired
	 * name. If a file with the same name is already existing that file will be
	 * deleted.
	 * 
	 * @param fileName
	 *            the file name
	 * @param content
	 *            the content
	 * @throws Exception
	 *             the exception
	 */
	public static void writeFile(String fileName, byte[] content)
			throws Exception {
		FileOutputStream fos = new FileOutputStream(fileName + ".filepart");
		int done = 0;
		while (content.length - done > 0) {
			if (content.length - done > maxBlockSize) {
				fos.write(content, done, maxBlockSize);
				done += maxBlockSize;
			} else {
				fos.write(content, done, content.length - done);
				done += content.length;
			}
		}
		fos.close();
		boolean ok = new File(fileName).delete();
		File file = new File(fileName + ".filepart");
		ok = file.renameTo(new File(fileName));
		if (!ok) {
			throw new RuntimeException("FileSaveFailed");
		}
	}

	/**
	 * Human readable byte count.
	 * 
	 * @param bytes
	 *            the bytes
	 * @param si
	 *            the si
	 * @return the string
	 */
	public static String humanReadableByteCount(long bytes, boolean si) {
		int unit = si ? 1000 : 1024;
		if (bytes < unit)
			return bytes + " B";
		int exp = (int) (Math.log(bytes) / Math.log(unit));
		String pre = (si ? "kMGTPE" : "KMGTPE").charAt(exp - 1)
				+ (si ? "" : "i");
		return String.format("%.1f %sB", bytes / Math.pow(unit, exp), pre);
	}

	/**
	 * Calculates the hash of a file.
	 * 
	 * @param file
	 *            the file
	 * @param hashType
	 *            the hash type. At least the following types are supported:
	 *            <ul>
	 *            <li>MD2</li>
	 *            <li>MD5</li>
	 *            <li>SHA-1</li>
	 *            <li>SHA-256</li>
	 *            <li>SHA-384</li>
	 *            <li>SHA-512</li>
	 *            </ul>
	 * @return the string
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 */
	public static String calcHash(File file, String hashType)
			throws IOException, NoSuchAlgorithmException {
		byte buf[] = new byte[maxBlockSize];
		MessageDigest md = MessageDigest.getInstance(hashType);
		md.reset();
		if (file.isFile()) {
			RandomAccessFile raf = new RandomAccessFile(file, "r");
			try {
				int len = 0;
				while ((len = raf.read(buf)) != -1) {
					md.update(buf, 0, len);
				}
			} finally {
				raf.close();
			}
		} else {
			md.update(file.getAbsolutePath().getBytes(), 0, file
					.getAbsolutePath().length());
		}

		byte[] hash = md.digest();
		return asHex(hash);
	}

	/**
	 * Convert the whole Argument buf[] in to a hexadecimal presentation
	 * 
	 * @param buf
	 *            the buf
	 * 
	 * @return the string
	 */
	public static String asHex(byte buf[]) {

		StringBuffer strbuf = new StringBuffer(buf.length * 2);

		for (final byte b : buf) {
			strbuf.append(HEXES[(b & 0xF0) >> 4]).append(HEXES[(b & 0x0F)]);
		}
		return strbuf.toString();
	}

	/**
	 * Gets the files and hashes.
	 * 
	 * @param baseFile
	 *            the base file
	 * @param hashType
	 *            the hash type
	 * @param basePath
	 *            the base path
	 * @return the files and hashes
	 * @throws Exception
	 *             the exception
	 */
	public static HashMap<String, String> getFilesAndHashes(File baseFile,
			String hashType, String basePath) throws Exception {
		HashMap<String, String> filesAndHashes = new HashMap<String, String>();

		if (baseFile.isDirectory()) {
			for (File file : baseFile.listFiles()) {
				filesAndHashes.putAll(getFilesAndHashes(file, hashType,
						basePath));
			}
		} else {
			filesAndHashes
			.put(baseFile.getAbsolutePath().replaceAll("\\\\", "/")
					.replaceFirst(basePath.replaceAll("\\\\", "/"), ""),
					calcHash(baseFile, hashType));
		}

		return filesAndHashes;
	}

	/**
	 * Copies the content of a file to another file.
	 * 
	 * @param filenameFrom
	 *            the filename from
	 * @param filenameTo
	 *            the filename to
	 * @throws FileNotFoundException
	 *             the file not found exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void copyWholeFile(String filenameFrom, String filenameTo)
			throws FileNotFoundException, IOException {

		RandomAccessFile fis = new RandomAccessFile(filenameFrom, "r");
		// If the parent directory of the destination file doesn't exist, try to
		// create it
		File f = new File(filenameTo);
		if (!f.getParentFile().exists()) {
			f.getParentFile().mkdirs();
		}
		boolean ok = f.delete();
		// ignore it if the delete was not successful (there may not even be an
		// old file there
		FileOutputStream fos = new FileOutputStream(filenameTo + ".filepart");
		byte[] content = new byte[maxBlockSize];

		try {
			int i = -1;
			while ((i = fis.read(content)) > 0) {
				fos.write(content, 0, i);
			}
		} finally {
			fis.close();
			fos.close();
		}
		File file = new File(filenameTo + ".filepart");
		ok = file.renameTo(new File(filenameTo));
		if (!ok) {
			throw new RuntimeException("FileCopy from " + filenameFrom + " to "
					+ filenameTo + " failed.");
		}
	}

	/**
	 * Counts the number of lines of a file The file is always closed.
	 * 
	 * @param fileName
	 *            the file to read, must not be {@code null}
	 * @throws IOException
	 *             in case of an I/O error
	 */
	public static int countLines(String fileName) throws IOException {

		FileReader f = new FileReader(fileName);
		BufferedReader reader = new BufferedReader(f);
		String line = reader.readLine();
		int count = 0;
		while (line != null) {
			count++;
			line = reader.readLine();
		}
		reader.close();
		return count;

	}

	/**
	 * List the elements of the directory and its sub-directories.
	 * 
	 * Return a list of the files
	 * 
	 */
	public static List<File> listFiles(File directory) {
		List<File> l = new ArrayList<File>();
		File listOfFiles[] = directory.listFiles();
		if (listOfFiles != null) {
			for (File f : listOfFiles) {
				if (f.isDirectory()) {
					l.addAll(listFiles(f));
				} else {
					l.add(f);
				}
			}
		}
		return l;
	}

	public static File createTempDirectory() throws IOException {

		File baseDir = new File(System.getProperty("java.io.tmpdir"));
		File resultDir = File.createTempFile("UC4", "ARATools", baseDir);

		if (!(resultDir.delete())) {
			throw new IOException("Could not delete temp file: "
					+ resultDir.getAbsolutePath());
		}

		if (!resultDir.mkdirs()) {
			throw new IOException("Failed to create tmp directory.");
		}
		return resultDir;

	}

	public static void copyDirectory(File sourceLocation , File targetLocation) throws IOException {
		if (sourceLocation.isDirectory()) {
			if (!targetLocation.exists()) {
				targetLocation.mkdir();
			}

			String[] children = sourceLocation.list();
			for (int i=0; i<children.length; i++) {
				copyDirectory(new File(sourceLocation, children[i]),
						new File(targetLocation, children[i]));
			}
		} else {

			InputStream in = new FileInputStream(sourceLocation);
			OutputStream out = new FileOutputStream(targetLocation);

			// Copy the bits from instream to outstream
			byte[] buf = new byte[1024];
			int len;
			while ((len = in.read(buf)) > 0) {
				out.write(buf, 0, len);
			}
			in.close();
			out.close();
		}
	}

	/**
	 * @param sourceFile
	 * @param destFile
	 * 			The file's absolute path after being moved
	 */
	public static void moveFile(File sourceFile, File destFile){
		InputStream inStream = null;
		OutputStream outStream = null;

		try{
			inStream = new FileInputStream(sourceFile);
			outStream = new FileOutputStream(destFile);

			byte[] buffer = new byte[1024];

			int length;
			//copy the file content in bytes
			while ((length = inStream.read(buffer)) > 0){
				outStream.write(buffer, 0, length);
			}
			inStream.close();
			outStream.close();

			//delete the original file
			sourceFile.delete();

		}catch(IOException e){
			e.printStackTrace();
		}
	}

	public static String normalize(String uri) {
		if ("".equals(uri)) {
			return uri;
		}
		int leadingSlashes;
		for (leadingSlashes = 0 ; leadingSlashes < uri.length()
				&& uri.charAt(leadingSlashes) == '/' ; ++leadingSlashes) {}
		boolean isDir = (uri.charAt(uri.length() - 1) == '/');
		StringTokenizer st = new StringTokenizer(uri, "/");
		LinkedList clean = new LinkedList();
		while (st.hasMoreTokens()) {
			String token = st.nextToken();
			if ("..".equals(token)) {
				if (! clean.isEmpty() && ! "..".equals(clean.getLast())) {
					clean.removeLast();
					if (! st.hasMoreTokens()) {
						isDir = true;
					}
				} else {
					clean.add("..");
				}
			} else if (! ".".equals(token) && ! "".equals(token)) {
				clean.add(token);
			}
		}
		StringBuffer sb = new StringBuffer();
		while (leadingSlashes-- > 0) {
			sb.append('/');
		}
		for (Iterator it = clean.iterator() ; it.hasNext() ; ) {
			sb.append(it.next());
			if (it.hasNext()) {
				sb.append('/');
			}
		}
		if (isDir && sb.length() > 0 && sb.charAt(sb.length() - 1) != '/') {
			sb.append('/');
		}
		return sb.toString();
	}

	public static String generateRandomString(){
		char[] chars = "abcdefghijklmnopqrstuvwxyz".toCharArray();
		StringBuilder sb = new StringBuilder();
		Random random = new Random();
		for (int i = 0; i < 20; i++) {
			char c = chars[random.nextInt(chars.length)];
			sb.append(c);
		}
		return sb.toString();
	}
	public static boolean isBinary(File snap, String relativePath) {
		boolean ret = false;
		try {
			ZipInputStream zin = new ZipInputStream(new FileInputStream(snap));
			ZipEntry entry;
			String path = relativePath.replaceAll("\\\\", "/");
			while ((entry = zin.getNextEntry()) != null) {

				String entryName = entry.getName().replaceAll("\\\\", "/");

				if (entryName.equals(path)) {

					byte[] buffer = new byte[100];

					int read;
					read = zin.read(buffer, 0, buffer.length);
					for (int i = 0; i < read; i++) {
						if (buffer[i] == 0) {
							ret = true;
							break;
						}
					}

					break;

				}

				zin.closeEntry();

			}

			zin.close();

		} catch (IOException e) {

		}
		return ret;
	}
	/**
	 * check whether a file is binary file or not
	 * 
	 * @param f
	 *            the file need to check
	 * @return true if the file is binary false if the file is text
	 */
	public static boolean isBinary(File f) {
		boolean ret = false;
		try {
			InputStream in = new FileInputStream(f);
			byte[] buf = new byte[100];
			int read = in.read(buf, 0, buf.length);
			for (int i = 0; i < read; i++) {
				if (buf[i] == 0) {
					ret = true;
					break;
				}
			}

			in.close();

		} catch (FileNotFoundException e) {
		} catch (IOException e) {
		}

		return ret;
	}

	/**Convert input path's wildcards to java wildcards
	 * @param path
	 * @return
	 * 		converted directory. Ex: /dir1/dir2?/dir3? -> /dir1/dir2.?/dir3.?
	 */
	public static String convertWildCard(String path) {

		String[] regexChars = {".","$","^","+", "|","{","}","(",")","[","]","!","\\"};
		for(String regexChar : regexChars)
			path = path.replace(regexChar, '\\' + regexChar);

		path = path.replace("*", ".*");
		path = path.replace("?", ".{1}");

		return path;

	}

	/**
	 * @param path
	 * @return
	 * 		The solid path of the wildcard-contained input. Ex: /Users/dtn/Te?t/abc -> /Users/dtn/
	 */
	public static String getSourceWildCard(String path) {

		String src = "";
		int index1 = path.indexOf("*");
		int index2 = path.indexOf("?");

		if( index1 == -1 && index2 == -1 )
			return path;

		else if(index1 == -1 || (index2 != -1 && index2 < index1))
			src = path.substring(0,index2);

		else if(index2 == -1 || (index1 != -1 && index1 < index2))
			src = path.substring(0,index1);

		src = src.substring(0, src.lastIndexOf("/") + 1);

		return src;

	}

	public static boolean verifyDirExists(File file) {
		if (file.exists() && file.isDirectory()) {
			return true;
		}
		else {
			FeatureUtil.logMsg(file.getAbsolutePath() + " not found");
			return false;
		}
	}

	public static boolean verifyDirWritable(File dir) {
		File file = new File(dir, "temp.txt");
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(file);
			return true;
		} catch (Exception e) {
			FeatureUtil.logMsg(e.getMessage());
			return false;
		} finally {
			file.deleteOnExit();
			try {
				if (fos != null)
					fos.close();
			} catch (IOException e) {
				FeatureUtil.logMsg(e.getMessage());
				return false;
			}
		}
	}
	
	/*
	 * check if file exist
	 */
	/** @param file
	 *            file to be verified
	 * @return true if file exist */
	public static boolean verifyFileExists(File file) {
		if (file.exists() && file.isFile()) {
			//FeatureUtil.dbgMsg(file.getAbsolutePath() + " found");
			return true;
		}
		else {
			FeatureUtil.dbgMsg(file.getAbsolutePath() + " not found");
			return false;
		}
	}
	
	public static FileLock lockFile(FileChannel channel) {
		FileLock lock = null;
		try {
			for (int i = 0; i < 50; i++) {
				try {
					lock = channel.tryLock();
					if (lock != null && lock.isValid()) {
						FeatureUtil.logMsg("...File released after " + i + " attempts.", MsgTypes.INFO);
						break;
					} else {
						FeatureUtil.logMsg("Could not get a lock on file, waiting for " + i*100 + " milliseconds.", MsgTypes.INFO);
						Thread.sleep(100);
					}
				} catch (OverlappingFileLockException e) {
					FeatureUtil.logMsg("INFO: File is locked by another process, retrying in " + i*100 + " milliseconds.");
					Thread.sleep(100);
				} catch (IOException e) {
					FeatureUtil.logMsg(e.getMessage(), MsgTypes.INFO);
					Thread.sleep(100);
				}
			}
		} catch (InterruptedException e) {
			FeatureUtil.logMsg(e);
			return null;
		}
		
		return lock;
	}
	
	public static FileLock lockFile(RandomAccessFile raf, int numberOfRetries, long waitTime) {
		FileChannel channel = raf.getChannel();
		FileLock lock = null;
		try {
			for (int i = 0; i < numberOfRetries; i++) {
				try {
					lock = channel.tryLock();
					if (lock != null && lock.isValid()) {
						FeatureUtil.logMsg("...File released after " + i + " attempts.", MsgTypes.INFO);
						break;
					} else {
						FeatureUtil.logMsg("Could not get a lock on file, waiting for " + i*100 + " milliseconds.", MsgTypes.INFO);
						Thread.sleep(waitTime);
					}
				} catch (OverlappingFileLockException e) {
					FeatureUtil.logMsg("INFO: File is locked by another process, retrying in " + i*100 + " milliseconds.");
					Thread.sleep(waitTime);
				} catch (IOException e) {
					FeatureUtil.logMsg(e.getMessage(), MsgTypes.INFO);
					Thread.sleep(100);
				}
			}
		} catch (InterruptedException e) {
			FeatureUtil.logMsg(e);
			return null;
		}
		
		return lock;
	}
	
	/**
     * Gets the name minus the path from a full filename.
     * <p>
     * This method will handle a file in either Unix or Windows format.
     * The text after the last forward or backslash is returned.
     * <pre>
     * a/b/c.txt --> c.txt
     * a.txt     --> a.txt
     * a/b/c     --> c
     * a/b/c/    --> ""
     * </pre>
     * <p>
     * The output will be the same irrespective of the machine that the code is running on.
     *
     * @param filename  the filename to query, null returns null
     * @return the name of the file without the path, or an empty string if none exists
     */
    public static String getName(String filename) {
        if (filename == null) {
            return null;
        }
        int index = indexOfLastSeparator(filename);
        return filename.substring(index + 1);
    }
	
	/**
     * Gets the extension of a filename.
     * <p>
     * This method returns the textual part of the filename after the last dot.
     * There must be no directory separator after the dot.
     * <pre>
     * foo.txt      --> "txt"
     * a/b/c.jpg    --> "jpg"
     * a/b.txt/c    --> ""
     * a/b/c        --> ""
     * </pre>
     * <p>
     * The output will be the same irrespective of the machine that the code is running on.
     *
     * @param filename the filename to retrieve the extension of.
     * @return the extension of the file or an empty string if none exists or {@code null}
     * if the filename is {@code null}.
     */
    public static String getExtension(String filename) {
        if (filename == null) {
            return null;
        }
        int index = indexOfExtension(filename);
        if (index == -1) {
            return "";
        } else {
            return filename.substring(index + 1);
        }
    }
    
    /**
     * Returns the index of the last extension separator character, which is a dot.
     * <p>
     * This method also checks that there is no directory separator after the last dot.
     * To do this it uses {@link #indexOfLastSeparator(String)} which will
     * handle a file in either Unix or Windows format.
     * <p>
     * The output will be the same irrespective of the machine that the code is running on.
     * 
     * @param filename  the filename to find the last path separator in, null returns -1
     * @return the index of the last separator character, or -1 if there
     * is no such character
     */
    public static int indexOfExtension(String filename) {
        if (filename == null) {
            return -1;
        }
        int extensionPos = filename.lastIndexOf(EXTENSION_SEPARATOR);
        int lastSeparator = indexOfLastSeparator(filename);
        return lastSeparator > extensionPos ? -1 : extensionPos;
    }
    
    /**
     * Returns the index of the last directory separator character.
     * <p>
     * This method will handle a file in either Unix or Windows format.
     * The position of the last forward or backslash is returned.
     * <p>
     * The output will be the same irrespective of the machine that the code is running on.
     * 
     * @param filename  the filename to find the last path separator in, null returns -1
     * @return the index of the last separator character, or -1 if there
     * is no such character
     */
    public static int indexOfLastSeparator(String filename) {
        if (filename == null) {
            return -1;
        }
        int lastUnixPos = filename.lastIndexOf(UNIX_SEPARATOR);
        int lastWindowsPos = filename.lastIndexOf(WINDOWS_SEPARATOR);
        return Math.max(lastUnixPos, lastWindowsPos);
    }

	public static String fileAsString(RandomAccessFile raf) {
		byte[] content = fileAsByteArray(raf);
		if (content == null)
			return "";
		return new String(content);
	}

	private static byte[] fileAsByteArray(RandomAccessFile raf) {
		byte[] content;
		try {
			content = new byte[(int) raf.length()];
			int read = 0;
			do {
				int offset = 0;
				read = raf.read(content, offset, content.length - offset);
				offset += read;
			} while (read != -1);
		} catch (IOException e) {
			return null;
		}
		return content;	
	}

	public static void copyToTargetFile(HttpHost target, HttpGet httpGet, HttpResponse response, String path, InputStream is, String to, Boolean overwrite) throws IOException, FileDoesNotExistException {
		// Check if target file exists
		File localFile = new File(to);
		File pf = localFile.getParentFile();

		if (localFile.isDirectory()) {
			String fileName = path.substring(path.lastIndexOf("/") > 0 ? path.lastIndexOf("/") : 0, path.length());
			localFile = new File(localFile, fileName);
		}
		if (localFile.exists())
			if (overwrite) {
				FeatureUtil.logMsg("'" + localFile.getAbsolutePath()
						+ "' already exists!. Deleting ...");
				if (localFile.isDirectory())
					FileUtil.deleteDirectory(localFile);
				else
					localFile.delete();
			} else {
				FeatureUtil
						.logMsg(localFile.getAbsolutePath()
								+ " already exists and overwrite is set to NO. Aborting ...");
				throw new FileAlreadyExistsException(localFile.getAbsolutePath()
						+ " already exists and overwrite is set to NO. Aborting ...");
			}

		if (!pf.isDirectory() && !pf.mkdirs()) {
			FeatureUtil
					.logMsg("Local Directory "
							+ pf.getAbsolutePath()
							+ " does not exist or can't be created. Please check the path again. Aborting ...");
			throw new FileDoesNotExistException("Local Directory "
					+ pf.getAbsolutePath()
					+ " does not exist or can't be created. Please check the path again. Aborting ...");
		}
		
		FeatureUtil.logMsg("Copying " + getName(localFile.getAbsolutePath()) + FILENAME_SPLITTER + "'"  + target.toString() + httpGet.getURI().getPath() + "' => '" + localFile.getAbsolutePath() + "'");

		OutputStream os = new FileOutputStream(localFile);
		byte[] buff = new byte[4096];
		int len;

		try {
			while (-1 != (len = is.read(buff)))
				os.write(buff, 0, len);

		} catch (IOException e) {
			FeatureUtil
					.logMsg("IOException occured while copying file. Aborting ...");
			throw new IOException();
		} finally {
			os.flush();
			os.close();
			is.close();
			EntityUtils.consume(response.getEntity());
			httpGet.releaseConnection();
		}
	}
}
