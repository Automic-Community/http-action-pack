/**---------------------------------------
 *  AraFileCmd.java
 *
 *  Author: Roger Talkov
 *
 * Copyright (C) 2011 UC4 Software, Inc.  All Rights Reserved.
 *
 * Last check in $Date: 2011-12-07 15:35:51 -0800 (Wed, 07 Dec 2011) $
 * by $Author: rtalkov $
 * $Rev: 27244 $
 */
package com.uc4.ara.feature;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.uc4.ara.feature.FeatureUtil.MsgTypes;
import com.uc4.ara.feature.cipher.Password;
import com.uc4.ara.feature.globalcodes.ErrorCodes;
import com.uc4.ara.feature.utils.CommandLineWrapper;
import com.uc4.ara.feature.utils.Maxim;
import com.uc4.ara.util.Logger;

/**
 * Command line tool for ARA Deployment Management features
 * 
 * @author Roger Talkov
 * @version $Rev: 27244 $ $Date: 2011-12-07 15:35:51 -0800 (Wed, 07 Dec 2011) $
 */
public class AraFileCmd {
	public static final String PASSWORD_MARKER = "--10";
	public static final String PASSWORD_MARKER_DASH = "Â­Â­10";

	/**
	 * @param args
	 *            0 - feature name: Text, XML,... 1 - class name 2 - n
	 *            parameters to pass to the class
	 */
	public static void main(String[] args) {
		FeatureUtil.logMsg("http-tool", MsgTypes.GENERAL);
		FeatureUtil.logMsg("(c) Automic Software GmbH", MsgTypes.GENERAL);
		try {			
			FeatureUtil.logMsg("Version: "
					+ FeatureUtil.getCompiledVersion("http-tool"), MsgTypes.GENERAL);
			
			FeatureUtil.logMsg("Date: "
					+ FeatureUtil
					.getCompiledDate("http-tool"), MsgTypes.GENERAL);
			FeatureUtil.logMsg("");
		} catch (IOException ei) {
			// ignore the exception
		}
		try {
			//print general help message
			String pkg = AraFileCmd.class.getPackage().getName(); 
			
			if(args.length == 0)
				FeatureUtil.printGeneralHelp(pkg);
			else if (!FeatureUtil.packageExists(pkg, args[0]))
				FeatureUtil.printGeneralHelp(pkg);
			else if (args.length == 1)
				FeatureUtil.printPackageHelp(pkg, args[0]);
			else
			{
				if (args[0].toLowerCase().equals("arb")) {
					if(args.length > 2 && args[2].toLowerCase().equals("execute")) {
						String[] myArgs = new String[args.length - 2];
						for (int i = 3; i < args.length; i++)
							myArgs[i - 3] = args[i];
						execute(myArgs);
					} else if (args.length == 5 && args[2].toLowerCase().equals("cipher")) {
						Password executePassword = new Password();
						String[] myArgs = new String[2];
						myArgs[0] = args[3];
						myArgs[1] = args[4];
						executePassword.run(myArgs);
					} else {
						FeatureUtil.logMsg("Usage:");
						FeatureUtil.logMsg("Execute: arb -cmd execute %COMMAND%");
						FeatureUtil.logMsg("Password: arb -cmd cipher encrypt/decrypt text/password");
					}
	
				}else{
					// package
					String className = pkg + '.' + args[0].toLowerCase() + '.'
							+ args[1];
					try {
					Class<?> clazz = Class.forName(className);
					// strip off first 2 args
					String[] params = new String[args.length - 2];
					for (int i = 2, n = args.length; i < n; i++)
						params[i - 2] = args[i];
					
					if(IFeatureDeprecated.class.isAssignableFrom(clazz))
					{
						IFeatureDeprecated instance = (IFeatureDeprecated) clazz.newInstance();
						
						// handle password decryption
						params = handlePasswordDecryption(params);
						
						// check the parameters
						int ret = instance.checkParams(params);
						if (ret != ErrorCodes.OK) {
							FeatureUtil.logMsg("Parameter(s) invalid");
							instance.printUsage();
							System.exit(ret);
						}
						// perform the desired command
						try {
							ret = instance.run(params);
							FeatureUtil.logMsg("Return code: " + ret, MsgTypes.INFO);
							System.exit(ret);
						} catch (Exception e) {
							instance.printUsage();
							FeatureUtil.logMsg(e);
							instance.cleanupAfterException(e);
							System.exit(ErrorCodes.EXCEPTION);
						}
					} else {
						IFeature feature = (IFeature) clazz.newInstance();
						int errorCode = ErrorCodes.OK;
						try {
							feature.initialize();
							errorCode = feature.run(params);
						} catch(Exception e) {
							if(e.getClass().isAssignableFrom(IllegalStateException.class) && 
									!AbstractInternalFeature.class.isAssignableFrom(feature.getClass()))
								feature.printUsage();
							
							errorCode = ErrorCodes.EXCEPTION;
							
							Logger.logException(e);
						} finally {
							feature.finalize(errorCode);
							System.exit(errorCode);
						}
					}
					} catch(ClassNotFoundException ex) {
						FeatureUtil.logMsg("Could not find specified method: " + args[1]);
						System.exit(ErrorCodes.EXCEPTION);
					}
				}
			}
		} catch (Exception e) {
			FeatureUtil.logMsg(e);
			System.exit(ErrorCodes.EXCEPTION);
		}
	}

	private static String[] handlePasswordDecryption(String[] args) {
		for (int i = 0; i < args.length; i++) {
			args[i] = decryptPassword(args[i]);
		}
		return args;
	}

	private static String decryptPassword(String password) {
		if (password.startsWith(PASSWORD_MARKER) || password.startsWith(PASSWORD_MARKER_DASH)) {
			String clearText = Maxim.deMaxim(password);
			if (clearText.startsWith(PASSWORD_MARKER) || password.startsWith(PASSWORD_MARKER_DASH))
				password = Maxim.deMaxim(clearText);
			else
				password = clearText;
		}
		return password;
	}

	private static int execute(String[] args) throws IOException, InterruptedException {
		List<String> list = new ArrayList<String>();
		for (int i = 0; i < args.length; i++) {
			list.add(args[i]);
		}
		CommandLineWrapper.main(list.toArray(new String[list.size()]));
		return 0;
	}
}
