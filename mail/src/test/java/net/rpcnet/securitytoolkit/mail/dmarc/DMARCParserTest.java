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

class DMARCParserTest {

    @Test
    void parseEmptyDMARCResponse() {
        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(new Properties());
        assertTrue(dmarcResult.isEmpty());
    }

    @Test
    void parseVersionDMARCResponse() {
        Properties properties = new Properties();
        String version = "DMARC1";
        properties.put(VERSION_KEY, version);

        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(properties);
        assertFalse(dmarcResult.isEmpty());
        assertTrue(dmarcResult.get().getVersion().isPresent());
        assertEquals(version, dmarcResult.get().getVersion().get());
    }

    @Test
    void parsePercentagePartialDMARCResponse() {
        Properties properties = new Properties();
        String percentage = "100";
        properties.put(PERCENTAGE_KEY, percentage);

        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(properties);
        assertFalse(dmarcResult.isEmpty());
        assertTrue(dmarcResult.get().getPercentage().isPresent());
        assertEquals(percentage, dmarcResult.get().getPercentage().get());
    }

    @Test
    void parseForensicReportPartialDMARCResponse() {
        Properties properties = new Properties();
        String forensicReport = "mailto:webmaster@rpcnet.net";
        properties.put(FORENSIC_REPORT_KEY, forensicReport);

        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(properties);
        assertFalse(dmarcResult.isEmpty());
        assertTrue(dmarcResult.get().getForensicReport().isPresent());
        assertEquals(forensicReport, dmarcResult.get().getForensicReport().get());
    }

    @Test
    void parseAggregateReportPartialDMARCResponse() {
        Properties properties = new Properties();
        String aggregateReport = "mailto:webmaster@rpcnet.net";
        properties.put(AGGREGATE_REPORT_KEY, aggregateReport);

        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(properties);
        assertFalse(dmarcResult.isEmpty());
        assertTrue(dmarcResult.get().getAggregateReport().isPresent());
        assertEquals(aggregateReport, dmarcResult.get().getAggregateReport().get());
    }

    @Test
    void parsePolicyPartialDMARCResponse() {
        Properties properties = new Properties();
        String policy = "quarantine";
        properties.put(POLICY_KEY, policy);

        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(properties);
        assertFalse(dmarcResult.isEmpty());
        assertTrue(dmarcResult.get().getPolicy().isPresent());
        assertEquals(policy, dmarcResult.get().getPolicy().get());
    }

    @Test
    void parseSubDomainPolicyPartialDMARCResponse() {
        Properties properties = new Properties();
        String subDomainsPolicy = "reject";
        properties.put(SUBDOMAINS_POLICY_KEY, subDomainsPolicy);

        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(properties);
        assertFalse(dmarcResult.isEmpty());
        assertTrue(dmarcResult.get().getSubdomainsPolicy().isPresent());
        assertEquals(subDomainsPolicy, dmarcResult.get().getSubdomainsPolicy().get());
    }

    @Test
    void parseDomainKeysAlignmentPartialDMARCResponse() {
        Properties properties = new Properties();
        String domainKeysAlignment = "s";
        properties.put(DOMAIN_KEYS_ALIGNMENT_KEY, domainKeysAlignment);

        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(properties);
        assertFalse(dmarcResult.isEmpty());
        assertTrue(dmarcResult.get().getDomainKeysAlignment().isPresent());
        assertEquals(domainKeysAlignment, dmarcResult.get().getDomainKeysAlignment().get());
    }

    @Test
    void parseSPFAlignmentPartialDMARCResponse() {
        Properties properties = new Properties();
        String spfAlignment = "s";
        properties.put(SPF_ALIGNMENT_KEY, spfAlignment);

        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(properties);
        assertFalse(dmarcResult.isEmpty());
        assertTrue(dmarcResult.get().getSPFAlignment().isPresent());
        assertEquals(spfAlignment, dmarcResult.get().getSPFAlignment().get());
    }

    @Test
    void parseForensicReportingOptionsPartialDMARCResponse() {
        Properties properties = new Properties();
        String forensicReportingOptions = "1";
        properties.put(FORENSIC_REPORTING_OPTIONS_KEY, forensicReportingOptions);

        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(properties);
        assertFalse(dmarcResult.isEmpty());
        assertTrue(dmarcResult.get().getForensicReportingOptions().isPresent());
        assertEquals(forensicReportingOptions, dmarcResult.get().getForensicReportingOptions().get());
    }

    @Test
    void parseReportFormatPartialDMARCResponse() {
        Properties properties = new Properties();
        String reportFormat = "afrf";
        properties.put(REPORT_FORMAT_KEY, reportFormat);

        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(properties);
        assertFalse(dmarcResult.isEmpty());
        assertTrue(dmarcResult.get().getReportFormat().isPresent());
        assertEquals(reportFormat, dmarcResult.get().getReportFormat().get());
    }

    @Test
    void parseAggregateReportTimeIntervalPartialDMARCResponse() {
        Properties properties = new Properties();
        String aggregateReportTimeInterval = "86400";
        properties.put(AGGREGATE_REPORT_TIME_INTERVAL_KEY, aggregateReportTimeInterval);

        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(properties);
        assertFalse(dmarcResult.isEmpty());
        assertTrue(dmarcResult.get().getAggregateReportTimeInterval().isPresent());
        assertEquals(aggregateReportTimeInterval, dmarcResult.get().getAggregateReportTimeInterval().get());
    }

    @Test
    void parseCompleteDMARCResponse(){
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

        assertTrue(dmarcResult.get().getVersion().isPresent());
        assertEquals(version, dmarcResult.get().getVersion().get());
        assertTrue(dmarcResult.get().getPercentage().isPresent());
        assertEquals(percentage, dmarcResult.get().getPercentage().get());
        assertTrue(dmarcResult.get().getForensicReport().isPresent());
        assertEquals(forensicReport, dmarcResult.get().getForensicReport().get());
        assertTrue(dmarcResult.get().getAggregateReport().isPresent());
        assertEquals(aggregateReport, dmarcResult.get().getAggregateReport().get());
        assertTrue(dmarcResult.get().getPolicy().isPresent());
        assertEquals(policy, dmarcResult.get().getPolicy().get());
        assertTrue(dmarcResult.get().getSubdomainsPolicy().isPresent());
        assertEquals(subDomainsPolicy, dmarcResult.get().getSubdomainsPolicy().get());
        assertTrue(dmarcResult.get().getDomainKeysAlignment().isPresent());
        assertEquals(domainKeysAlignment, dmarcResult.get().getDomainKeysAlignment().get());
        assertTrue(dmarcResult.get().getSPFAlignment().isPresent());
        assertEquals(spfAlignment, dmarcResult.get().getSPFAlignment().get());
        assertTrue(dmarcResult.get().getForensicReportingOptions().isPresent());
        assertEquals(forensicReportingOptions, dmarcResult.get().getForensicReportingOptions().get());
        assertTrue(dmarcResult.get().getReportFormat().isPresent());
        assertEquals(reportFormat, dmarcResult.get().getReportFormat().get());
        assertTrue(dmarcResult.get().getAggregateReportTimeInterval().isPresent());
        assertEquals(aggregateReportTimeInterval, dmarcResult.get().getAggregateReportTimeInterval().get());
    }

    @Test
    void parseNonStringProperties() {
        Properties properties = new Properties();
        properties.put(VERSION_KEY, new StringBuilder());
        properties.put(PERCENTAGE_KEY, new StringBuilder());
        properties.put(FORENSIC_REPORT_KEY, new StringBuilder());
        properties.put(AGGREGATE_REPORT_KEY, new StringBuilder());
        properties.put(POLICY_KEY, new StringBuilder());
        properties.put(SUBDOMAINS_POLICY_KEY, new StringBuilder());
        properties.put(DOMAIN_KEYS_ALIGNMENT_KEY, new StringBuilder());
        properties.put(SPF_ALIGNMENT_KEY, new StringBuilder());
        properties.put(FORENSIC_REPORTING_OPTIONS_KEY, new StringBuilder());
        properties.put(REPORT_FORMAT_KEY, new StringBuilder());
        properties.put(AGGREGATE_REPORT_TIME_INTERVAL_KEY, new StringBuilder());
        Optional<DMARCResult> dmarcResult = DMARCParser.parseDMARCResponse(properties);
        assertTrue(dmarcResult.isEmpty());
    }

}