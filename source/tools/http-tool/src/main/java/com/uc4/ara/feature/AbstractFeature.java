/* 
 * (c) 2012 Michael Schwartz e.U. 
 * All Rights Reserved.
 * 
 * This program is not a free software. The owner of the copyright
 * can license the software for you. You may not use this file except in
 * compliance with the License. In case of questions please
 * do not hesitate to contact us at idx@mschwartz.eu.
 * 
 * Filename: AbstractFeature.java
 * Created: 22.06.2012
 * 
 * Author: $LastChangedBy$ 
 * Date: $LastChangedDate$ 
 * Revision: $LastChangedRevision$ 
 */
package com.uc4.ara.feature;

import com.uc4.ara.feature.FeatureUtil.MsgTypes;
import com.uc4.ara.feature.globalcodes.ErrorCodes;

/**
 * base class for ARA features.
 * 
 * @author Roger Talkov
 * @version $Rev: 27244 $ $Date: 2011-12-07 15:35:51 -0800 (Wed, 07 Dec 2011) $
 */
public abstract class AbstractFeature implements IFeatureDeprecated {

	public static final String AUTOMATION_ENGINE_DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";

	/**
	 * convenience method.
	 * 
	 * @param msg
	 *            the msg
	 * @see FeatureUtil#logMsg(String)
	 */
	public void logMsg(String msg) {
		FeatureUtil.logMsg(msg);
	}

	/**
	 * convenience method.
	 * 
	 * @param msg
	 *            the msg
	 * @param type
	 *            the type
	 * @see FeatureUtil#logMsg(String, MsgTypes)
	 */
	public static void logMsg(String msg, MsgTypes type) {
		FeatureUtil.logMsg(msg, type);
	}

	/**
	 * convenience method.
	 * 
	 * @param t
	 *            the t
	 * @see FeatureUtil#logMsg(Throwable)
	 */
	public void logMsg(Throwable t) {
		FeatureUtil.logMsg(t);
	}

	/**
	 * convenience method.
	 * 
	 * @param msg
	 *            the msg
	 * @see FeatureUtil#dbgMsg(String)
	 */
	public void dbgMsg(String msg) {
		FeatureUtil.dbgMsg(msg);
	}

	/**
	 * Checks the validity of the parameters. This method should be overwritten
	 * to check if all parameters are syntactically correct.
	 * 
	 * @param args
	 *            the args
	 * @return ErrorCodes.OK or ErrorCodes.PARAMSMISMATCH
	 */
	protected int checkParamsValidity(String[] args) {
		return ErrorCodes.OK;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.uc4.ara.feature.IFeature#checkParams(java.lang.String[])
	 */
	@Override
	public int checkParams(String[] args) {
		if (args.length < getMinParams())
			return ErrorCodes.PARAMSMISMATCH;
		if (args.length > getMaxParams())
			return ErrorCodes.PARAMSMISMATCH;
		int res = checkParamsValidity(args);
		return res;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.uc4.ara.feature.IFeature#cleanupAfterException(java.lang.Exception)
	 */
	@Override
	public void cleanupAfterException(Exception e) {
		// do nothing here
	}
}
