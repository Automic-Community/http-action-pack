package com.uc4.ara.feature.cipher;

import com.uc4.ara.feature.AbstractFeature;
import com.uc4.ara.feature.FeatureUtil;
import com.uc4.ara.feature.globalcodes.ErrorCodes;
import com.uc4.ara.feature.utils.Maxim;

public class Password extends AbstractFeature {

	public int run(String[] args) throws Exception {
		String command = args[0];
		String argumentText = args[1];
		
		System.out.println("Length Input: " + argumentText.length());
		
		if(command.toLowerCase().trim().equals("encrypt")) {
			String encrypted = Maxim.enMaxim(argumentText, true);
			System.out.println("Encrypted: " + encrypted);
			System.out.println("Length Encrypted: " + encrypted.length());
		}
		if(command.toLowerCase().trim().equals("decrypt")){
			String decrypted = Maxim.deMaxim(argumentText);
			System.out.println("Decrypted: " + decrypted);
			System.out.println("Length Decrypted: " + decrypted.length());
		}
		
		return ErrorCodes.OK;
	}

	@Override
	public int getMinParams() {
		return 2;
	}

	@Override
	public int getMaxParams() {
		return 2;
	}

	@Override
	public void printUsage() {
		FeatureUtil.logMsg("Command:");
		FeatureUtil.logMsg("cipher Password encrypt/decrypt text/password");
	}

}
