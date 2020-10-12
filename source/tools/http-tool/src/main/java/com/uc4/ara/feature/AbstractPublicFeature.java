/**
 * 
 */
package com.uc4.ara.feature;

import java.util.Calendar;

import com.uc4.ara.feature.globalcodes.ErrorCodes;
import com.uc4.ara.feature.utils.CmdLineParser;
import com.uc4.ara.util.Logger;

/**
 * @author extsts
 *
 */
public abstract class AbstractPublicFeature implements IFeature {

    protected Calendar startTime = null;
    protected CmdLineParser parser = new CmdLineParser();
    protected CmdLineParser.Option<String> loglevel;
    protected String loglevelValue = null;

    protected static final String LOGLEVEL_DEFAULT = "ERROR";

    @Override
    public void initialize() {
        //define the loglevel parameter
        loglevel = parser.addHelp(
                parser.addStringOption("ll", "loglevel", false),
                "The log level for this execution. Defines the amount of information that is logged. Possible values: DEBUG, INFO & ERROR");

    }

    @Override
    public int run(String[] args) throws Exception
    {
        //log header
        startTime = Calendar.getInstance();
        Logger.logHeader(this.getClass().getSimpleName(), startTime);

        //parse arguments - if parameter ar not valid an excption is thrown
        parser.parse(args);
        parser.printParams();
        //set loglevelvalue
        loglevelValue = parser.getOptionValue(loglevel);
        if(loglevelValue == null)
            loglevelValue = LOGLEVEL_DEFAULT;

        return ErrorCodes.OK;
    }

    @Override
    public void finalize(int errorCode) {
        //log footer
        Logger.logFooter(getPackageNameFromClass(), this.getClass().getSimpleName(), startTime, Calendar.getInstance(), errorCode);
    }

    @Override
    public void printUsage()
    {
        parser.printUsage(getPackageNameFromClass(), this.getClass().getSimpleName());
    }

    @Override
    public void printDescription(boolean isOneliner)
    {
        parser.printDescription(isOneliner);
    }

    private String getPackageNameFromClass()
    {
        String className = this.getClass().getName();
        int index = className.lastIndexOf('.');
        if(index > 0)
            return className.substring(className.lastIndexOf('.', index - 1) + 1, index);

        return "";
    }

}
