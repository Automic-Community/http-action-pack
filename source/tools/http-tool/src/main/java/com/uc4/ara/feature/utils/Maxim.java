package com.uc4.ara.feature.utils;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Portierung von ZUSTRNG_DeMaxim
 * 
 * @author ??? */
public class Maxim {
	/** Decodes a passwort in the INI file
	 * 
	 * @param value
	 *            encrypted String
	 * @return readable text
	 * @throws RuntimeException
	 *             in case of an error */
	public static String deMaxim(String value) {
		if (!value.startsWith("Â­Â­10") && !value.startsWith("--10"))
			return value; //not a password
		try {
			byte[] key = "zP7Qn%9x".getBytes("ISO-8859-1"); //8 byte key, Giraffchen
			Key secretKey = new SecretKeySpec(key, "DES");
			byte[] input = hexStringToByteArray(value.substring(4));
			Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] result = cipher.doFinal(input);
			//find 0 byte
			int len = 0;
			for (int i = 0; i < result.length; i++) {
				if (result[i] == 0) {
					len = i;
					break;
				}
			}
			if(len == 0)
				len = result.length;
			byte[] text = new byte[len];
			System.arraycopy(result, 0, text, 0, len);
			return new String(text, "ISO-8859-1");
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static String enMaxim(String value) {
		return enMaxim(value, false);
	}

	public static String enMaxim(String value, boolean simple) {
		try {
			byte[] key = "zP7Qn%9x".getBytes("ISO-8859-1");
			Key secretKey = new SecretKeySpec(key, "DES");
			byte[] input = value.getBytes();
			int n = input.length;
			while (n % 8 != 0)
				n++;
			byte[] ninput = new byte[n];
			System.arraycopy(input, 0, ninput, 0, input.length);
			Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] result = cipher.doFinal(ninput);
			if (simple)
				return "--10" + binToHexString(result);
			return "Â­Â­10" + binToHexString(result);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/** Creates a Hex String from a byte array
	 * 
	 * @param data
	 *            Byte array
	 * @return String */
	public static String binToHexString(byte[] data) {
		return binToHexString(data, data.length);
	}

	/** Creates a byte array from a Hex String
	 * 
	 * @param data
	 *            String
	 * @return byte array */
	public static byte[] hexStringToByteArray(String text) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if (Character.isLetterOrDigit(c))
				builder.append(c);
		}
		String data = builder.toString();
		if (data.length() % 2 != 0)
			return null;
		byte[] ret = new byte[data.length() / 2];
		int c = 0;
		for (int i = 0; i < data.length(); i += 2) {
			String hex = data.substring(i, i + 2);
			ret[c] = (byte) Integer.parseInt(hex, 16);
			c++;
		}
		return ret;
	}

	public static String binToHexString(byte[] data, int maxLen) {
		StringBuilder ret = new StringBuilder();
		binToHexString(ret, data, maxLen);
		return ret.toString();
	}

	public static void binToHexString(StringBuilder st, byte[] data, int maxLen) {
		if (data == null)
			return;
		if (data.length < maxLen)
			maxLen = data.length;
		for (int i = 0; i < maxLen; i++) {
			String hex = Integer.toHexString(data[i] & 0xFF);
			if (hex.length() == 1)
				st.append('0');
			st.append(hex);
		}
		if (data.length != maxLen)
			st.append("...");
	}
}
