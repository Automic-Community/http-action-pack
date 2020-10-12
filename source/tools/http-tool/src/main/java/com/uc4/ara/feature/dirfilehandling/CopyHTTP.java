/*
 * (c) 2012 Michael Schwartz e.U.
 * All Rights Reserved.
 * 
 * This program is not a free software. The owner of the copyright
 * can license the software for you. You may not use this file except in
 * compliance with the License. In case of questions please
 * do not hesitate to contact us at idx@mschwartz.eu.
 * 
 * Filename: CopyHTTP.java
 * Created: 20.09.2012
 * 
 * Author: $LastChangedBy$
 * Date: $LastChangedDate$
 * Revision: $LastChangedRevision$
 */
package com.uc4.ara.feature.dirfilehandling;

import java.io.*;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;

import com.uc4.ara.feature.FeatureUtil;
import com.uc4.ara.feature.globalcodes.ErrorCodes;
import com.uc4.ara.feature.utils.FileUtil;

public class CopyHTTP extends AbstractCopy {

	private final boolean secure;

	public CopyHTTP(String host, int port, String username, String password,
			String from, String to, boolean overwrite, long timeout,
			String proxyHost, int proxyPort, String proxyUser,
			String proxyPassword, boolean secure) {

		super(host, port, username, password, from, false, to, overwrite,
				timeout, false, proxyHost, proxyPort, proxyUser, proxyPassword,
				null, null);
		this.secure = secure;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.uc4.ara.feature.dirfilehandling.AbstractCopy#copy()
	 */
	@Override
	public int retrieve() throws Exception {

		normalizeURLPath();
		String encodeURL = encodeURLPathAndQuery();

		String schema = "http" + (secure ? "s" : "");
		HttpHost target = new HttpHost(host, port, schema);

		HttpParams httpParams = new BasicHttpParams();
		HttpConnectionParams.setConnectionTimeout(httpParams, (int) timeout);

		DefaultHttpClient httpclient = new DefaultHttpClient(httpParams);
		// circumvent the SSL authentication exception
		httpclient = new WebClientDevWrapper().wrapClient(httpclient);

		if (hasBasicAuthen()) {
			addBasicAuthenInfo(target, httpclient);
		}

		if (isConnectViaProxy()) {
			setUpProxyParameter(httpclient);
		}

		HttpGet httpGet = new HttpGet(encodeURL);

		HttpResponse response;
		try {
			response = httpclient.execute(target, httpGet);
		} catch (UnknownHostException ex) {
			FeatureUtil.logMsg("Cannot connect to '" + target.toString() + "'. Unknown host.");
			return ERROR_CODE_HOST_NOT_FOUND;
		}

		int statusCode = response.getStatusLine().getStatusCode();

		if (isNotSuccessStatus(statusCode)) {
			FeatureUtil.logMsg("Received status code " + statusCode
					+ ". Message: " + response.getStatusLine()
					+ ". Aborting ...");

			// 4xx/5xx will be return as standard HTTP error response codes
			// (e.g. site not found,..)
			if (statusCode > 300) {
				return statusCode;
			}
			return ErrorCodes.ERROR;
		}

		String path = httpGet.getURI().getPath();
		InputStream is = response.getEntity().getContent();
		FileUtil.copyToTargetFile(target, httpGet, response, path, is, to, overwrite);

		return ErrorCodes.OK;
	}

	private void addBasicAuthenInfo(HttpHost target, DefaultHttpClient httpclient) {
		httpclient.getCredentialsProvider().setCredentials(
                new AuthScope(target),
                new UsernamePasswordCredentials(username, password));
	}

	private boolean isNotSuccessStatus(int statusCode) {
		return statusCode < 200 || statusCode > 300;
	}

	private void setUpProxyParameter(DefaultHttpClient httpclient) {
		HttpHost proxy = new HttpHost(proxyHost, proxyPort, "http");
		httpclient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY,
                proxy);

		if (proxyUser != null && proxyUser.length() > 0) {

            httpclient.getCredentialsProvider().setCredentials(
                    new AuthScope(proxy),
                    new UsernamePasswordCredentials(proxyUser,
                            proxyPassword));
        }
	}

	private boolean isConnectViaProxy() {
		return proxyHost != null && proxyHost.length() > 0;
	}

	private boolean hasBasicAuthen() {
		return username != null && username.length() > 0;
	}

	private void normalizeURLPath() {
		if (!from.startsWith("/") && !from.startsWith("\\"))
			from = "/" + from;

		from = from.replaceAll("\\\\", "/");
		from = FileUtil.normalize(from);

		if (from.endsWith("/"))
			from = from.substring(0, from.length() - 1);
	}

	private String encodeURLPathAndQuery() {
		StringBuilder urlPath = new StringBuilder(from.split("[^&?]*?=[^&?]*")[0]);
		List<String> listParam = new ArrayList<>();
		Matcher m = Pattern.compile("[^&?]*?=[^&?]*").matcher(from);
		while (m.find()){
			listParam.add(m.group());
		}
		Map<String, String> requestParams = new HashMap<>();
		for (String param: listParam) {
			String splitParam[] = param.split("=");
			requestParams.put(splitParam[0],splitParam[1]);
		}

		Set<String> requestParamsKeySet = requestParams.keySet();
		Set<String> outputParamKeySet = new HashSet<>();
		for (String key :requestParamsKeySet) {
			outputParamKeySet.add(encodeValue(key) + "=" + encodeValue(requestParams.get(key)));
		}

		for (String opk: outputParamKeySet){
			urlPath.append("&").append(opk);
		}

		return urlPath.toString();
	}

	private String encodeValue(String s) {
		String return_string = null;
		try {
			return_string = URLEncoder.encode(s, StandardCharsets.UTF_8.toString());
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return return_string;
	}

	@Override
	public int store() throws Exception {
		throw new UnsupportedOperationException();
	}

	public class WebClientDevWrapper {

		DefaultHttpClient wrapClient(HttpClient base)
				throws NoSuchAlgorithmException, KeyManagementException {
			SSLContext ctx = SSLContext.getInstance("TLS");
			X509TrustManager tm = new X509TrustManager() {

				@Override
				public void checkClientTrusted(X509Certificate[] xcs,
						String string) throws CertificateException {
				}

				@Override
				public void checkServerTrusted(X509Certificate[] xcs,
						String string) throws CertificateException {
				}

				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return null;
				}
			};
			ctx.init(null, new TrustManager[] { tm }, null);
			SSLSocketFactory ssf = new SSLSocketFactory(ctx,
					SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
			ClientConnectionManager ccm = base.getConnectionManager();
			SchemeRegistry sr = ccm.getSchemeRegistry();
			sr.register(new Scheme("https", 443, ssf));

			return new DefaultHttpClient(ccm, base.getParams());
		}
	}

}
