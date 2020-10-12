package com.uc4.ara.util;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.concurrent.TimeUnit;

import com.uc4.ara.feature.FeatureUtil;

public class Logger {

	public final static String DATE_FORMAT_NOW = "yyyy-MM-dd HH:mm:ss";
	
	public static void logHeader(String className, Calendar cal) {
		SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT_NOW);
		
		String timeOfExecution = "";
		if(cal != null)
			timeOfExecution = sdf.format(cal.getTime());
		else
			timeOfExecution = sdf.format(Calendar.getInstance().getTime());
		
		StringBuilder builder = new StringBuilder();
		
		builder.append("Executing ").append(className).append(" started\r\n");
		builder.append("Started at ").append(timeOfExecution).append("\r\n");
		builder.append("=================================================\r\n\r\n");
		
		FeatureUtil.logMsg(builder.toString());
	}

	public static void logFooter(String packageName, String className, Calendar startTime, Calendar endTime, int errorCode) {
		StringBuilder builder = new StringBuilder();
		
		SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT_NOW);
		
		String endOfExecution = ""; 
		if(endTime != null)
			endOfExecution = sdf.format(endTime.getTime());
		else
			endOfExecution = sdf.format(Calendar.getInstance().getTime());
		
		String elapsedTimeString = "0 min, 0 sec";
		if(startTime != null) {
			long elapsedTime = endTime.getTimeInMillis() - startTime.getTimeInMillis();
			elapsedTimeString = String.format("%d min, %d sec", 
			    TimeUnit.MILLISECONDS.toMinutes(elapsedTime),
			    TimeUnit.MILLISECONDS.toSeconds(elapsedTime) - 
			    TimeUnit.MINUTES.toSeconds(TimeUnit.MILLISECONDS.toMinutes(elapsedTime))
			);
		}
		
		builder.append("\r\n\r\n=================================================\r\n");
		builder.append("Executing ").append(packageName).append(" ").append(className).append(" finished\r\n");
		builder.append("Ended at ").append(endOfExecution).append("\r\n");
		builder.append("Elapsed Time: ").append(elapsedTimeString).append("\r\n");
		builder.append("Return Code: ").append(errorCode).append("\r\n");
		
		FeatureUtil.logMsg(builder.toString());
	}

	public static void logException(Exception e) {
		StringBuilder builder = new StringBuilder();
		
		builder.append("\r\n\r\n=================================================\r\n");
		builder.append("Exception ").append(e.getClass().getSimpleName()).append(" occured\r\n");
		builder.append("Message: ").append(e.getMessage()).append("\r\n");
		builder.append("Detailed Information: \r\n");

		FeatureUtil.logMsg(builder.toString());
		FeatureUtil.logMsg(e);
		
	}
	
	public static void log(String message, String logLevel) {
		FeatureUtil.logMsg(message);
	}
	
	public static void logDebug(String message, String logLevel) {
		if(logLevel.equals("DEBUG"))
			FeatureUtil.logMsg(message);
	}
	
	public static void logInfo(String message, String logLevel) {
		if(logLevel.equals("DEBUG") || logLevel.equals("INFO"))
			FeatureUtil.logMsg(message);
	}
}
