/*
 * (c) 2012 Michael Schwartz e.U.
 * All Rights Reserved.
 * 
 * This program is not a free software. The owner of the copyright
 * can license the software for you. You may not use this file except in
 * compliance with the License. In case of questions please
 * do not hesitate to contact us at idx@mschwartz.eu.
 * 
 * Filename: PutFiles.java
 * Created: 25.09.2012
 * 
 * Author: $LastChangedBy$
 * Date: $LastChangedDate$
 * Revision: $LastChangedRevision$
 */
package com.uc4.ara.feature.dirfilehandling;

import com.uc4.ara.feature.AbstractPublicFeature;
import com.uc4.ara.feature.FeatureUtil;
import com.uc4.ara.feature.globalcodes.ErrorCodes;
import com.uc4.ara.feature.utils.CmdLineParser;
import com.uc4.ara.util.Logger;

/**
 * The Class PutFiles.
 */
public class PutFiles extends AbstractPublicFeature {

    protected CmdLineParser.Option<String> protocol;
    protected CmdLineParser.Option<String> host;
    protected CmdLineParser.Option<String> port;
    protected CmdLineParser.Option<String> username;
    protected CmdLineParser.Option<String> password;
    protected CmdLineParser.Option<String> from;
    protected CmdLineParser.Option<String> recursive;
    protected CmdLineParser.Option<String> to;
    protected CmdLineParser.Option<String> overwrite;
    protected CmdLineParser.Option<String> timeout;
    protected CmdLineParser.Option<String> preserve;

    protected CmdLineParser.Option<String> proxyHost;
    protected CmdLineParser.Option<String> proxyPort;
    protected CmdLineParser.Option<String> proxyUsername;
    protected CmdLineParser.Option<String> proxyPassword;
    protected CmdLineParser.Option<String> transferMode;
    protected CmdLineParser.Option<String> smbDomainName;

    @Override
    public void initialize() {
        super.initialize();

        protocol = parser.addHelp(parser.addStringOption("prc", "protocol", true),
                "Protocol used to put file/directory to remote machine. HTTP(S), FTP(S), SCP, SFTP, SMB are supported.");

        host = parser.addHelp(parser.addStringOption("h", "host", true),
                "Hostname or IP address of the target machine (i.e. targetmachine.com, 192.168.1.2).");

        port = parser.addHelp(parser.addStringOption("p", "port", false),
                "Port number of the target machine. Defaut: 80(http), 443(https), 21(ftp), 990(ftps), 22(scp/sftp), 139(smb). ");

        username = parser.addHelp(parser.addStringOption("u", "username", false),
                "Optional username if the target machine requires authentication.");

        password = parser.addHelp(parser.addPasswordOption("pwd", "password", false),
                "Optional password if the target machine requires authentication.");

        from = parser.addHelp(parser.addStringOption("src", "source", true),
                "Source file/directory to be uploaded. For HTTP(S), source package must be a file.");

        to = parser.addHelp(parser.addStringOption("tgt", "target", true),
                "Target file/directory of the uploaded package. (i.e. C:\\source_dir => /root/target_dir, C:\\source_file.txt => /root/target_file.txt, " +
                "C:\\source_file.txt => /root/target_dir/) .");

        preserve = parser.addHelp(parser.addStringOption("prv", "preserve", false),
                "If set to YES, file properties(last modified, read/write permission) would be preserved after being uploaded. Default: NO");

        recursive = parser.addHelp(parser.addStringOption("r", "recursive", false),
                "If set to NO, only direct children of the local directory would be uploaded. Default: YES");

        overwrite = parser.addHelp(parser.addStringOption("o", "overwrite", false),
                "If set to YES, existing remote files would be overwritten by local files. Default: YES");

        timeout = parser.addHelp(parser.addStringOption("to", "timeout", false),
                "Maximum waiting time for the remote machine to be connected. Default: 5000 ms.");

        proxyHost = parser.addHelp(parser.addStringOption("ph", "proxyHost", false),
                "Host name or IP of the proxy host if used (i.e. proxyhost.com, 192.168.1.2). Only HTTP proxies are supported. For HTTP(S)/FTP(S) only. ");

        proxyPort = parser.addHelp(parser.addStringOption("pp", "proxyPort", false),
                "Proxy port to use. For HTTP(S)/FTP(S) only. ");

        proxyUsername = parser.addHelp(parser.addStringOption("pu", "proxyUsername", false),
                "Optional username used to authenticate with proxy server. For HTTP(S)/FTP(S) only.");

        proxyPassword = parser.addHelp(parser.addPasswordOption("ppwd", "proxyPassword", false),
                "Optional password used to authenticate with proxy server. For HTTP(S)/FTP(S) only.");

        transferMode = parser.addHelp(parser.addStringOption("tm", "transfermode", false),
                "For FTP(S) only. BINARY/TEXT: the data transferred is treated as a binary stream/textual information (charset conversion). Default: BINARY.");

        smbDomainName = parser.addHelp(parser.addStringOption("smbDN", "smbdomainname", false),
                "For SMB only. Domain name (FQDN) of the source machine (i.e. sbb01.spoc.global). Required if source machine belongs to a windows domain. ");

    }

    /* (non-Javadoc)
     * @see com.uc4.ara.feature.IFeature#run(java.lang.String[])
     */
    @Override
    public int run(String[] args) throws Exception {
        super.run(args);

        String protocolValue = parser.getOptionValue(protocol);
        String hostValue = parser.getOptionValue(host);
        int portValue = -1;
        try {
            portValue = Integer.parseInt(parser.getOptionValue(port));
        } catch (NumberFormatException e) {
            Logger.log("Cannot get Port value, use Default Value: 80(http), 443(https), 21(ftp), 990(ftps), 22(scp/sftp), 139(smb).", this.loglevelValue);
        }

        String usernameValue = parser.getOptionValue(username);
        String passwordValue = parser.getOptionValue(password);
        String fromValue = parser.getOptionValue(from);
        String toValue = parser.getOptionValue(to);

        String recursiveStr = parser.getOptionValue(recursive);
        String overwriteStr = parser.getOptionValue(overwrite);
        String perserveStr = parser.getOptionValue(preserve);

        boolean recursiveValue = recursiveStr !=null && recursiveStr.equalsIgnoreCase("no") ? false : true;
        boolean overwriteValue = overwriteStr != null && overwriteStr.equalsIgnoreCase("yes") ? true : false;
        boolean preserveValue = perserveStr != null && perserveStr.equalsIgnoreCase("yes") ? true : false;

        long timeoutValue = 5000;
        try {
            timeoutValue = Integer.parseInt(parser.getOptionValue(timeout));
        } catch (NumberFormatException e) {
            Logger.log("Cannot get Timeout value, use Default Value: 5000", this.loglevelValue);
        }

        //HTTP(S)/ FTP(S) only
        String proxyHostValue = null;
        int proxyPortValue = 80;
        String proxyUserValue = null;
        String proxyPasswordValue = null;

        if(protocolValue.equalsIgnoreCase("HTTP") ||
                protocolValue.equalsIgnoreCase("HTTPS") ){

            proxyHostValue = parser.getOptionValue(proxyHost);
            if(proxyHostValue != null)
                try {
                    proxyPortValue = Integer.parseInt(parser.getOptionValue(proxyPort));
                } catch (NumberFormatException e) {
                    Logger.log("Cannot get Proxy Port value, use Default Value: 80", this.loglevelValue);
                }
            proxyUserValue = parser.getOptionValue(proxyUsername);
            proxyPasswordValue = parser.getOptionValue(proxyPassword);
        }

        int errorCode = ErrorCodes.OK;
        AbstractCopy abstractCopy = null;

        if (protocolValue.equals("HTTP"))
            abstractCopy = new CopyHTTP(hostValue, portValue, usernameValue, passwordValue, fromValue, toValue,
                    overwriteValue, timeoutValue, proxyHostValue, proxyPortValue, proxyUserValue, proxyPasswordValue, false);

        else if (protocolValue.equals("HTTPS"))
            abstractCopy = new CopyHTTP(hostValue, portValue, usernameValue, passwordValue, fromValue, toValue,
                    overwriteValue, timeoutValue, proxyHostValue, proxyPortValue, proxyUserValue, proxyPasswordValue, true);

        else {
            FeatureUtil.logMsg("Unknown Protocol '" + protocol + "'. " +
                    "Only support HTTP(S), FTP(S), SCP, SFTP, SMB. Aborting ...");
            return ErrorCodes.PARAMSMISMATCH;
        }

        errorCode = abstractCopy.store();
        return errorCode;
    }

}
