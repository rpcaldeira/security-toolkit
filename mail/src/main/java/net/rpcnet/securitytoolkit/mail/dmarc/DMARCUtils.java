package net.rpcnet.securitytoolkit.mail.dmarc;

public final class DMARCUtils {

    public static final String DMARC_DELIMIER = ";";

    public static final String VERSION_KEY = "v";
    public static final String PERCENTAGE_KEY = "pct";
    public static final String FORENSIC_REPORT_KEY = "ruf";
    public static final String AGGREGATE_REPORT_KEY = "rua";
    public static final String POLICY_KEY = "p";
    public static final String SUBDOMAIN_POLICY_KEY = "sp";
    public static final String DOMAIN_KEYS_ALIGNMENT_KEY = "adkim";
    public static final String SPF_ALIGNMENT_KEY = "aspf";
    public static final String FORENSIC_REPORTING_OPTIONS_KEY = "fo";
    public static final String REPORT_FORMAT_KEY = "rf";
    public static final String AGGREGATE_REPORT_TIME_INTERVAL_KEY = "ri";

    private DMARCUtils(){
        //Private utility class constructor
    }
}
