package com.uc4.ara.feature.dirfilehandling;

import java.io.File;

import com.uc4.ara.feature.AbstractFeature;
import com.uc4.ara.feature.globalcodes.ErrorCodes;
import com.uc4.ara.feature.utils.FileUtil;

public class CompareFeature extends AbstractFeature {

	@Override
	public int run(String[] args) throws Exception {
		int errorCode = ErrorCodes.OK;
		
		String basePath = args[0];
		String comparePath = args[1];
		String hashType = args[2];
		String failIf = args[4];
		
		String baseHash = "";
		String compareHash = "";
		
		File baseFile = new File(basePath);
		File compareFile = new File(comparePath);
		
		if(baseFile.exists() && baseFile.canRead()) {
			if(compareFile.exists() && compareFile.canRead()) {
				if(baseFile.isFile() && compareFile.isFile()) {
					baseHash = FileUtil.calcHash(baseFile, hashType);
					compareHash = FileUtil.calcHash(compareFile, hashType);
					
					if(baseHash.equals(compareHash)) {
						this.logMsg("Diff-Count: 0");
						if ("same".equalsIgnoreCase(failIf)) errorCode = ErrorCodes.ERROR;
					} else {
						this.logMsg("Diff-Count: 1");
						if ("different".equalsIgnoreCase(failIf)) errorCode = ErrorCodes.ERROR;
					}
				} else if(baseFile.isDirectory() && compareFile.isDirectory()) {
					DirectoryCompareFeature dcf = new DirectoryCompareFeature();
					errorCode = dcf.run(args);
				} else {
					errorCode = ErrorCodes.ERROR;
					this.logMsg("ERROR: Invalid Compare! Cannot compare file to directory.");
				}
			} else {
				errorCode = ErrorCodes.SEVERE;
				this.logMsg("ERROR: Compare-File " + comparePath + " does not exist or cannot be read!");
			}
		} else {
			errorCode = ErrorCodes.SEVERE;
			this.logMsg("ERROR: Base-File " + basePath + " does not exist or cannot be read!");
		}
			
		return errorCode;
	}

	@Override
	public int getMinParams() {
		return 5;
	}

	@Override
	public int getMaxParams() {
		return 5;
	}

	@Override
	public void printUsage() {
		// TODO Auto-generated method stub

	}

}
