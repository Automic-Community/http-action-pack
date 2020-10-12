package com.uc4.ara.feature.dirfilehandling;

import java.io.File;

public abstract class AbstractCopy {

    protected static final int ERROR_CODE_HOST_NOT_FOUND = 1;
    protected static final int ERROR_CODE_CONNECTION_TIMEOUT = 2;
    protected static final int ERROR_CODE_CONNECTION_IS_REFUSED = 3;
    protected static final int ERROR_CODE_FILE_NOT_FOUND = 4;
    protected static final int ERROR_CODE_FILE_COULD_NOT_BE_WRITTEN = 5;
    
	protected int errorCode;

	protected String host; // Hostname or IP address
	protected int port;
	protected String username; // Username of the target machine
	protected String password; // Password of the target machine
	protected String from; // The file/directory that will be used
	protected boolean recursive; // Recursively download files/directories if "from" is a directory. Unused for HTTP(S)
	protected String to; // where to download the file/directory to
	protected boolean overwrite; // Overwrite if file/directory already exists
	protected long timeout;
	protected boolean preserve; // Preserve file modification time and permission after being transferred. Unused for HTTP(S)

	protected String proxyHost; // Used for HTTP(S)/FTP(S) if a proxy server is required
	protected int proxyPort;
	protected String proxyUser;
	protected String proxyPassword;
	protected String transferMode; // Used for FTP(S) only. Binary or Text
	protected String smbDomainName; // SMB only. Used if the target machine belongs to a domain

	protected AbstractCopy(String host, int port, String username,
			String password, String from, boolean recursive, String to,
			boolean overwrite, long timeout, boolean preserve, String proxyHost, int proxyPort,
			String proxyUser, String proxyPassword, String transferMode, String smbDomainName) {
		super();
		this.host = host;
		this.port = port;
		this.username = username;
		this.password = password;
		this.from = from;
		this.recursive = recursive;
		this.to = to;
		this.overwrite = overwrite;
		this.timeout = timeout;
		this.preserve = preserve;
		this.proxyHost = proxyHost;
		this.proxyPort = proxyPort;
		this.proxyUser = proxyUser;
		this.proxyPassword = proxyPassword;

		this.transferMode = transferMode;
		this.smbDomainName = smbDomainName;
	}

	public abstract int retrieve() throws Exception;

	public abstract int store() throws Exception;

	protected void createParentDir(File localFile) throws UserException {
		File pf = localFile.getParentFile();
		pf.mkdirs();
		if(!pf.isDirectory())
			throw new UserException("Local Directory " + pf.getAbsolutePath()  + " can't be created. Please check the path again.");

	}

	protected class UserException extends Exception {
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;

		public UserException(String message) {
			super(message);
		}
	}

}
