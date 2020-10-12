/* 
 * (c) 2012 Michael Schwartz e.U. 
 * All Rights Reserved.
 * 
 * This program is not a free software. The owner of the copyright
 * can license the software for you. You may not use this file except in
 * compliance with the License. In case of questions please
 * do not hesitate to contact us at idx@mschwartz.eu.
 * 
 * Filename: GetFileChecksumFeature.java
 * Created: 12.09.2012
 * 
 * Author: $LastChangedBy$ 
 * Date: $LastChangedDate$ 
 * Revision: $LastChangedRevision$ 
 */
package com.uc4.ara.feature.dirfilehandling;

import java.io.File;

import com.uc4.ara.feature.AbstractFeature;
import com.uc4.ara.feature.FeatureUtil;
import com.uc4.ara.feature.FeatureUtil.MsgTypes;
import com.uc4.ara.feature.globalcodes.ErrorCodes;
import com.uc4.ara.feature.utils.FileUtil;

/**
 * The Class GetFileChecksumFeature generates a checksum for the content of a
 * file. At least the following hashtypes are supported:
 * <ul>
 * <li>MD2</li>
 * <li>MD5</li>
 * <li>SHA-1</li>
 * <li>SHA-256</li>
 * <li>SHA-384</li>
 * <li>SHA-512</li>
 * </ul>
 */
public class GetFileChecksumFeature extends AbstractFeature {

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.uc4.ara.feature.IFeature#run(java.lang.String[])
	 */
	@Override
	public int run(String[] args) throws Exception {
		int errorCode = ErrorCodes.OK;

		String filePath = args[0];
		String hashType = args[1];

		File file = new File(filePath);
		if (FileUtil.verifyFileExists(file)) {
			String fileHash = FileUtil.calcHash(file, hashType);
			FeatureUtil.logMsg("Checksum-Result: " + fileHash, MsgTypes.INFO);
		} else {
			errorCode = ErrorCodes.SEVERE;
			FeatureUtil.logMsg(String.format("File %s does not exist or not a normal file", filePath), MsgTypes.ERROR);
		}

		return errorCode;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.uc4.ara.feature.IFeature#getMinParams()
	 */
	@Override
	public int getMinParams() {
		return 2;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.uc4.ara.feature.IFeature#getMaxParams()
	 */
	@Override
	public int getMaxParams() {
		return 2;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.uc4.ara.feature.IFeature#printUsage()
	 */
	@Override
	public void printUsage() {
		this.logMsg("dirfilehandling command:");
		this.logMsg("GetFileChecksumFeature <filePath> <hashtype>");
	}

}
