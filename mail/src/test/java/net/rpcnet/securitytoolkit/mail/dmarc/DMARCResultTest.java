package net.rpcnet.securitytoolkit.mail.dmarc;

import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Properties;

import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.AGGREGATE_REPORT_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.AGGREGATE_REPORT_TIME_INTERVAL_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.DOMAIN_KEYS_ALIGNMENT_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.FORENSIC_REPORTING_OPTIONS_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.FORENSIC_REPORT_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.PERCENTAGE_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.POLICY_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.REPORT_FORMAT_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.SPF_ALIGNMENT_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.SUBDOMAINS_POLICY_KEY;
import static net.rpcnet.securitytoolkit.mail.dmarc.DMARCUtils.VERSION_KEY;
import static org.junit.jupiter.api.Assertions.*;

class DMARCResultTest {

    @Test
    void toStringTest(){
        Properties properties = new Properties();

        String version = "DMARC1";
        properties.put(VERSION_KEY, version);
        String percentage = "100";
        properties.put(PERCENTAGE_KEY, percentage);
        String forensicReport = "mailto:webmaster@rpcnet.net";
        properties.put(FORENSIC_REPORT_KEY, forensicReport);
        String aggregateReport = "mailto:webmaster@rpcnet.net";
        properties.put(AGGREGATE_REPORT_KEY, aggregateReport);
        String policy = "quarantine";
        properties.put(POLICY_KEY, policy);
        String subDomainsPolicy = "reject";
        properties.put(SUBDOMAINS_POLICY_KEY, subDomainsPolicy);
        String domainKeysAlignment = "s";
        properties.put(DOMAIN_KEYS_ALIGNMENT_KEY, domainKeysAlignment);
        String spfAlignment = "s";
        properties.put(SPF_ALIGNMENT_KEY, spfAlignment);
        String forensicReportingOptions = "1";
        properties.put(FORENSIC_REPORTING_OPTIONS_KEY, forensicReportingOptions);
        String reportFormat = "afrf";
        properties.put(REPORT_FORMAT_KEY, reportFormat);
        String aggregateReportTimeInterval = "86400";
        properties.put(AGGREGATE_REPORT_TIME_INTERVAL_KEY, aggregateReportTimeInterval);

        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(properties);
        assertFalse(dmarcResult.isEmpty());

        assertEquals("v=DMARC1;pct=100;ruf=mailto:webmaster@rpcnet.net;rua=mailto:webmaster@rpcnet.net;p=quarantine;sp=reject;adkim=s;aspf=s;rf=afrf;ri=86400;fo=1", dmarcResult.get().toString());
    }

}