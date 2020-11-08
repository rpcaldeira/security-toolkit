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

        if(this.getVersion().isPresent()){
            list.add(VERSION_KEY + EQUAL_SIGN + this.getVersion().get());
        }
        if(this.getPercentage().isPresent()){
            list.add(PERCENTAGE_KEY + EQUAL_SIGN + this.getPercentage().get());
        }
        if(this.getForensicReport().isPresent()){
            list.add(FORENSIC_REPORT_KEY + EQUAL_SIGN + this.getForensicReport().get());
        }
        if(this.getAggregateReport().isPresent()){
            list.add(AGGREGATE_REPORT_KEY + EQUAL_SIGN + this.getAggregateReport().get());
        }
        if(this.getPolicy().isPresent()){
            list.add(POLICY_KEY + EQUAL_SIGN + this.getPolicy().get());
        }
        if(this.getSubdomainsPolicy().isPresent()){
            list.add(SUBDOMAINS_POLICY_KEY + EQUAL_SIGN + this.getSubdomainsPolicy().get());
        }
        if(this.getDomainKeysAlignment().isPresent()){
            list.add(DOMAIN_KEYS_ALIGNMENT_KEY + EQUAL_SIGN + this.getDomainKeysAlignment().get());
        }
        if(this.getSPFAlignment().isPresent()){
            list.add(SPF_ALIGNMENT_KEY + EQUAL_SIGN + this.getSPFAlignment().get());
        }
        if(this.getReportFormat().isPresent()){
            list.add(REPORT_FORMAT_KEY + EQUAL_SIGN + this.getReportFormat().get());
        }
        if(this.getAggregateReportTimeInterval().isPresent()){
            list.add(AGGREGATE_REPORT_TIME_INTERVAL_KEY + EQUAL_SIGN + this.getAggregateReportTimeInterval().get());
        }
        if(this.getForensicReportingOptions().isPresent()){
            list.add(FORENSIC_REPORTING_OPTIONS_KEY + EQUAL_SIGN + this.getForensicReportingOptions().get());
        }

        return String.join(DMARC_DELIMIER, list);
    }
}
