package net.rpcnet.securitytoolkit.mail.dmarc;

import org.immutables.value.Value;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

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

@Value.Immutable
public abstract class DMARCResult {

    public static final String EQUAL_SIGN = "=";

    public abstract Optional<String> getVersion();
    public abstract Optional<String> getPercentage();
    public abstract Optional<String> getForensicReport();
    public abstract Optional<String> getAggregateReport();
    public abstract Optional<String> getPolicy();
    public abstract Optional<String> getSubdomainsPolicy();
    public abstract Optional<String> getDomainKeysAlignment();
    public abstract Optional<String> getSPFAlignment();
    public abstract Optional<String> getReportFormat();
    public abstract Optional<String> getAggregateReportTimeInterval();
    public abstract Optional<String> getForensicReportingOptions();

    @Override
    public String toString() {
        List<String> list = new ArrayList<>();

        getVersion().ifPresent(s -> list.add(VERSION_KEY + EQUAL_SIGN + s));
        getPercentage().ifPresent(s -> list.add(PERCENTAGE_KEY + EQUAL_SIGN + s));
        getForensicReport().ifPresent(s -> list.add(FORENSIC_REPORT_KEY + EQUAL_SIGN + s));
        getAggregateReport().ifPresent(s -> list.add(AGGREGATE_REPORT_KEY + EQUAL_SIGN + s));
        getPolicy().ifPresent(s -> list.add(POLICY_KEY + EQUAL_SIGN + s));
        getSubdomainsPolicy().ifPresent(s -> list.add(SUBDOMAINS_POLICY_KEY + EQUAL_SIGN + s));
        getDomainKeysAlignment().ifPresent(s -> list.add(DOMAIN_KEYS_ALIGNMENT_KEY + EQUAL_SIGN + s));
        getSPFAlignment().ifPresent(s -> list.add(SPF_ALIGNMENT_KEY + EQUAL_SIGN + s));
        getReportFormat().ifPresent(s -> list.add(REPORT_FORMAT_KEY + EQUAL_SIGN + s));
        getAggregateReportTimeInterval().ifPresent(s -> list.add(AGGREGATE_REPORT_TIME_INTERVAL_KEY + EQUAL_SIGN + s));
        getForensicReportingOptions().ifPresent(s -> list.add(FORENSIC_REPORTING_OPTIONS_KEY + EQUAL_SIGN + s));

        return String.join(DMARC_DELIMIER, list);
    }
}
