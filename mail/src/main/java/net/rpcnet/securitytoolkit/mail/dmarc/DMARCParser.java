package net.rpcnet.securitytoolkit.mail.dmarc;

import java.util.Optional;
import java.util.Properties;
import java.util.StringTokenizer;

import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.AGGREGATE_REPORT_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.AGGREGATE_REPORT_TIME_INTERVAL_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.DMARC_DELIMIER;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.DOMAIN_KEYS_ALIGNMENT_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.FORENSIC_REPORTING_OPTIONS_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.FORENSIC_REPORT_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.PERCENTAGE_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.POLICY_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.REPORT_FORMAT_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.SPF_ALIGNMENT_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.SUBDOMAIN_POLICY_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.VERSION_KEY;

public final class DMARCParser {

    public static final String PROPERTIES_DELIMITER = "=";

    private DMARCParser(){
        //Private utility class constructor
    }

    public static Properties parseDMARCProperties(String dnsResponse) {
        StringTokenizer stringTokenizer = new StringTokenizer(dnsResponse, DMARC_DELIMIER);
        Properties properties = new Properties();
        while (stringTokenizer.hasMoreElements()) {
            Object obj = stringTokenizer.nextElement();
            if(obj instanceof String){
                String str = (String) obj;
                String[] split = str.split(PROPERTIES_DELIMITER);
                properties.put(split[0], split[1]);
            }
        }
        return properties;
    }

    public static Optional<DMARCResult> parseDMARCResponse(String dmarcResponse){
        return parseDMARCResponse(DMARCParser.parseDMARCProperties(dmarcResponse));
    }

    public static Optional<DMARCResult> parseDMARCResponse(Properties properties){
        ImmutableDMARCResult.Builder builder = ImmutableDMARCResult.builder();

        if(properties.containsKey(VERSION_KEY)){
            builder.version(properties.getProperty(VERSION_KEY));
        }

        if(properties.containsKey(PERCENTAGE_KEY)){
            builder.percentage(properties.getProperty(PERCENTAGE_KEY));
        }

        if(properties.containsKey(FORENSIC_REPORT_KEY)){
            builder.forensicReport(properties.getProperty(FORENSIC_REPORT_KEY));
        }

        if(properties.containsKey(AGGREGATE_REPORT_KEY)){
            builder.aggregateReport(properties.getProperty(AGGREGATE_REPORT_KEY));
        }

        if(properties.containsKey(POLICY_KEY)){
            builder.policy(properties.getProperty(POLICY_KEY));
        }

        if(properties.containsKey(SUBDOMAIN_POLICY_KEY)){
            builder.subdomainPolicy(properties.getProperty(SUBDOMAIN_POLICY_KEY));
        }

        if(properties.containsKey(DOMAIN_KEYS_ALIGNMENT_KEY)){
            builder.domainKeysAlignment(properties.getProperty(DOMAIN_KEYS_ALIGNMENT_KEY));
        }

        if(properties.containsKey(SPF_ALIGNMENT_KEY)){
            builder.sPFAlignment(properties.getProperty(SPF_ALIGNMENT_KEY));
        }

        if(properties.containsKey(FORENSIC_REPORTING_OPTIONS_KEY)){
            builder.forensicReportingOptions(properties.getProperty(FORENSIC_REPORTING_OPTIONS_KEY));
        }

        if(properties.containsKey(REPORT_FORMAT_KEY)){
            builder.reportFormat(properties.getProperty(REPORT_FORMAT_KEY));
        }

        if(properties.containsKey(AGGREGATE_REPORT_TIME_INTERVAL_KEY)){
            builder.aggregateReportTimeInterval(properties.getProperty(AGGREGATE_REPORT_TIME_INTERVAL_KEY));
        }

        return Optional.of(builder.build());

    }

}
