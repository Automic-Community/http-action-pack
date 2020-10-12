/* 
 * (c) 2012 Michael Schwartz e.U. 
 * All Rights Reserved.
 * 
 * This program is not a free software. The owner of the copyright
 * can license the software for you. You may not use this file except in
 * compliance with the License. In case of questions please
 * do not hesitate to contact us at idx@mschwartz.eu.
 * 
 * Filename: IFeature.java
 * Created: 22.06.2012
 * 
 * Author: $LastChangedBy$ 
 * Date: $LastChangedDate$ 
 * Revision: $LastChangedRevision$ 
 */
package com.uc4.ara.feature;

import com.uc4.ara.feature.globalcodes.ErrorCodes;

/**
 * The Interface IFeature.
 * 
 * @author Roger Talkov
 * @version $Rev: 27244 $ $Date: 2011-12-07 15:35:51 -0800 (Wed, 07 Dec 2011) $
 */
public interface IFeatureDeprecated {

	/**
	 * Runs the feature.
	 * 
	 * @param args
	 *            the args
	 * @return the returncode
	 * @throws Exception
	 *             the exception
	 * @see ErrorCodes
	 */
	int run(String[] args) throws Exception;

	/**
	 * Gets the minimum number of parameters needed for this feature.
	 * 
	 * @return the min params
	 */
	int getMinParams();

	/**
	 * Gets the maximum number of parameters needed for this feature.
	 * 
	 * @return the max params
	 */
	int getMaxParams();

	/**
	 * Checks the parameters for validity.
	 * 
	 * @param args
	 *            the args
	 * @return the returncode
	 * @see ErrorCodes
	 */
	public int checkParams(String[] args);

	/**
	 * Prints the usage of the feature.
	 */
	public void printUsage();

	/**
	 * Provides a hook to be able to Cleanup when an exception occured.
	 * 
	 * @param e
	 *            the exception which has been thrown
	 */
	public void cleanupAfterException(Exception e);
}
