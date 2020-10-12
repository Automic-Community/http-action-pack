package com.uc4.ara.feature.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import com.uc4.ara.feature.AraFileCmd;
import com.uc4.ara.feature.FeatureUtil;
import com.uc4.ara.feature.FeatureUtil.MsgTypes;
import com.uc4.ara.feature.globalcodes.ErrorCodes;
import com.uc4.ara.feature.utils.Maxim;

/** Creates a new Process and decryptes the encoded command line parameter.
 * 
 * @author ang */
public class CommandLineWrapper {
	public static void main(String argv[]) throws IOException, InterruptedException {
		if (argv.length == 0) {
			FeatureUtil.logMsg("Argument missing", MsgTypes.ERROR);
			System.exit(ErrorCodes.SEVERE);
		}
		List<String> cmd = new ArrayList<String>(argv.length);
		for (String s : argv) {
			if(s != null) {
				if(s.contains(AraFileCmd.PASSWORD_MARKER) && s.contains("@")) {
					int beginIndex = s.indexOf(AraFileCmd.PASSWORD_MARKER); 
					int endIndex = s.indexOf("@");
					
					if(endIndex > beginIndex) {
						String password = s.substring(beginIndex, endIndex);
						String clearText = Maxim.deMaxim(password);
						
						s = s.replaceAll(password, clearText);
					}
					
					cmd.add(s);
				} else
					cmd.add(Maxim.deMaxim(s));
			}
		}
		ProcessBuilder builder = new ProcessBuilder(cmd);
		builder.redirectErrorStream(true);
		Process p = builder.start();
		final InputStream in = p.getInputStream();
		Runnable run = new Runnable() {
			public void run() {
				byte[] buffer = new byte[1024];
				try {
					int len;
					while ((len = in.read(buffer)) != -1) {
						System.out.write(buffer, 0, len);
					}
				}
				catch (IOException e) {
					e.printStackTrace();
				}
			}
		};
		new Thread(run).start();
		p.getOutputStream().close();
		System.exit(p.waitFor());		
	}
}
