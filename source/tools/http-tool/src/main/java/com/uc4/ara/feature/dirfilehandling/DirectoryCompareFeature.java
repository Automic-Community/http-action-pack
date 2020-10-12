package com.uc4.ara.feature.dirfilehandling;

import java.io.File;
import java.util.HashMap;

import com.uc4.ara.feature.AbstractFeature;
import com.uc4.ara.feature.globalcodes.ErrorCodes;
import com.uc4.ara.feature.utils.FileUtil;

public class DirectoryCompareFeature extends AbstractFeature {

	@Override
	public int run(String[] args) throws Exception {
int errorCode = ErrorCodes.OK;
		
		String basePath = args[0];
		String comparePath = args[1];
		String hashType = args[2];
		String outputType = args[3];
		String failIf = args[4];
		
		int countDiffs = 0;
				
		File baseFile = new File(basePath);
		File compareFile = new File(comparePath);
		
		if(baseFile.isDirectory() && baseFile.exists() && baseFile.canRead()) {
			if(compareFile.isDirectory() && compareFile.exists() && compareFile.canRead()) {
				HashMap<String, String> baseFiles = FileUtil.getFilesAndHashes(baseFile, hashType, baseFile.getAbsolutePath());
				HashMap<String, String> compareFiles = FileUtil.getFilesAndHashes(compareFile, hashType, compareFile.getAbsolutePath());
				
				HashMap<String, String> filesAndStates = determineFileStatus(baseFiles, compareFiles);
				
				for(String file : filesAndStates.keySet()) {
					String state = filesAndStates.get(file);
					
					if(!state.toLowerCase().trim().equals("identical")) {
						countDiffs++;
					}
					
					if(outputType.toLowerCase().trim().equals("identical")) {
						if(state.toLowerCase().trim().equals("identical"))
							this.logMsg("File: " + file);
					} else if(outputType.toLowerCase().trim().equals("different")) {
						if(!state.toLowerCase().trim().equals("identical"))
							this.logMsg("File: " + file + ", " + state);
					} else if(outputType.toLowerCase().trim().equals("both")) {
						this.logMsg("File: " + file + ", " + state);
					} 
				}
				this.logMsg("Diff-Count: " + countDiffs);
				if (("same".equalsIgnoreCase(failIf) && countDiffs == 0) || ("different".equalsIgnoreCase(failIf) && countDiffs > 0)) {
					errorCode = ErrorCodes.ERROR;
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

	public HashMap<String, String> determineFileStatus(HashMap<String, String> baseFiles,
			HashMap<String, String> compareFiles) {
		HashMap<String, String> determinedFiles = new HashMap<String, String>();
		
		if(compareFiles != null && baseFiles != null && !compareFiles.isEmpty() && !baseFiles.isEmpty()) {
			for(String file : compareFiles.keySet()) {
				if(!baseFiles.containsKey(file))
					determinedFiles.put(file, "added");
			}
			
			for(String file : baseFiles.keySet()) {
				if(compareFiles.containsKey(file)) {
					String fileHash = baseFiles.get(file);
					String compareHash = compareFiles.get(file);
					
					if(fileHash.equals(compareHash))
						determinedFiles.put(file, "identical");
					else
						determinedFiles.put(file, "different");
				} else {
					determinedFiles.put(file, "missing");
				}
			}
		}
		return determinedFiles;
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
