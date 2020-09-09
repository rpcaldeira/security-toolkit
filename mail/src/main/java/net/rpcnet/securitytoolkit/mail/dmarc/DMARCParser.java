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
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.SUBDOMAINS_POLICY_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.VERSION_KEY;

public final class DMARCParser {

    public static final String PROPERTIES_DELIMITER = "=";

    private DMARCParser(){
        //Private utility class constructor
    }

    public static Properties parseDMARCProperties(String dnsResponse) {
        StringTokenizer stringTokenizer = new StringTokenizer(dnsResponse, DMARC_DELIMIER);
        Properties properties = new Properties();
        while (stringTokenizer.hasMoreTokens()) {
            String[] split = stringTokenizer.nextToken().split(PROPERTIES_DELIMITER);
            properties.put(split[0], split[1]);
        }
        return properties;
    }

    public static Optional<DMARCResult> parseDMARCResponse(String dmarcResponse){
        return parseDMARCResponse(DMARCParser.parseDMARCProperties(dmarcResponse));
    }

    public static Optional<DMARCResult> parseDMARCResponse(Properties properties){

        if(properties.isEmpty()){
            return Optional.empty();
        }

        ImmutableDMARCResult.Builder builder = getBuilder();

        boolean result = handleVersion(properties, builder);
        result |= handlePercentage(properties, builder);
        result |= handleForensicReport(properties, builder);
        result |= handleAggregateReport(properties, builder);
        result |= handlePolicy(properties, builder);
        result |= handleSubdomainsPolicy(properties, builder);
        result |= handleDomainKeysAlignment(properties, builder);
        result |= handleSPFAlignment(properties, builder);
        result |= handleForensicReportingOptions(properties, builder);
        result |= handleReportFormat(properties, builder);
        result |= handleAggregateReportTimeInterval(properties, builder);

        return result ? Optional.of(builder.build()) : Optional.empty();

    }

    private static ImmutableDMARCResult.Builder getBuilder() {
        ImmutableDMARCResult.Builder builder = ImmutableDMARCResult.builder();

        builder.version(Optional.empty());
        builder.percentage(Optional.empty());
        builder.forensicReport(Optional.empty());
        builder.aggregateReport(Optional.empty());
        builder.policy(Optional.empty());
        builder.subdomainsPolicy(Optional.empty());
        builder.domainKeysAlignment(Optional.empty());
        builder.sPFAlignment(Optional.empty());
        builder.forensicReportingOptions(Optional.empty());
        builder.reportFormat(Optional.empty());
        builder.aggregateReportTimeInterval(Optional.empty());

        return builder;
    }

    private static boolean handleAggregateReportTimeInterval(Properties properties, ImmutableDMARCResult.Builder builder) {
        if(properties.containsKey(AGGREGATE_REPORT_TIME_INTERVAL_KEY) && properties.getProperty(AGGREGATE_REPORT_TIME_INTERVAL_KEY) != null){
            builder.aggregateReportTimeInterval(properties.getProperty(AGGREGATE_REPORT_TIME_INTERVAL_KEY));
            return true;
        }
        return false;
    }

    private static boolean handleReportFormat(Properties properties, ImmutableDMARCResult.Builder builder) {
        if(properties.containsKey(REPORT_FORMAT_KEY) && properties.getProperty(REPORT_FORMAT_KEY) != null){
            builder.reportFormat(properties.getProperty(REPORT_FORMAT_KEY));
            return true;
        }
        return false;
    }

    private static boolean handleForensicReportingOptions(Properties properties, ImmutableDMARCResult.Builder builder) {
        if(properties.containsKey(FORENSIC_REPORTING_OPTIONS_KEY) && properties.getProperty(FORENSIC_REPORTING_OPTIONS_KEY) != null){
            builder.forensicReportingOptions(properties.getProperty(FORENSIC_REPORTING_OPTIONS_KEY));
            return true;
        }
        return false;
    }

    private static boolean handleSPFAlignment(Properties properties, ImmutableDMARCResult.Builder builder) {
        if(properties.containsKey(SPF_ALIGNMENT_KEY) && properties.getProperty(SPF_ALIGNMENT_KEY) != null){
            builder.sPFAlignment(properties.getProperty(SPF_ALIGNMENT_KEY));
            return true;
        }
        return false;
    }

    private static boolean handleDomainKeysAlignment(Properties properties, ImmutableDMARCResult.Builder builder) {
        if(properties.containsKey(DOMAIN_KEYS_ALIGNMENT_KEY) && properties.getProperty(DOMAIN_KEYS_ALIGNMENT_KEY) != null){
            builder.domainKeysAlignment(properties.getProperty(DOMAIN_KEYS_ALIGNMENT_KEY));
            return true;
        }
        return false;
    }

    private static boolean handleSubdomainsPolicy(Properties properties, ImmutableDMARCResult.Builder builder) {
        if(properties.containsKey(SUBDOMAINS_POLICY_KEY) && properties.getProperty(SUBDOMAINS_POLICY_KEY) != null){
            builder.subdomainsPolicy(properties.getProperty(SUBDOMAINS_POLICY_KEY));
            return true;
        }
        return false;
    }

    private static boolean handlePolicy(Properties properties, ImmutableDMARCResult.Builder builder) {
        if(properties.containsKey(POLICY_KEY) && properties.getProperty(POLICY_KEY) != null){
            builder.policy(properties.getProperty(POLICY_KEY));
            return true;
        }
        return false;
    }

    private static boolean handleAggregateReport(Properties properties, ImmutableDMARCResult.Builder builder) {
        if(properties.containsKey(AGGREGATE_REPORT_KEY) && properties.getProperty(AGGREGATE_REPORT_KEY) != null){
            builder.aggregateReport(properties.getProperty(AGGREGATE_REPORT_KEY));
            return true;
        }
        return false;
    }

    private static boolean handleForensicReport(Properties properties, ImmutableDMARCResult.Builder builder) {
        if(properties.containsKey(FORENSIC_REPORT_KEY) && properties.getProperty(FORENSIC_REPORT_KEY) != null){
            builder.forensicReport(properties.getProperty(FORENSIC_REPORT_KEY));
            return true;
        }
        return false;
    }

    private static boolean handlePercentage(Properties properties, ImmutableDMARCResult.Builder builder) {
        if(properties.containsKey(PERCENTAGE_KEY) && properties.getProperty(PERCENTAGE_KEY) != null){
            builder.percentage(properties.getProperty(PERCENTAGE_KEY));
            return true;
        }
        return false;
    }

    private static boolean handleVersion(Properties properties, ImmutableDMARCResult.Builder builder) {
        if(properties.containsKey(VERSION_KEY) && properties.getProperty(VERSION_KEY) != null){
            builder.version(properties.getProperty(VERSION_KEY));
            return true;
        }
        return false;
    }

}
