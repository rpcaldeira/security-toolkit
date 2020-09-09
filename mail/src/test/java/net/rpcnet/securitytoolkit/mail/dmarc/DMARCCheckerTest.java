package net.rpcnet.securitytoolkit.mail.dmarc;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class DMARCCheckerTest {

    @Test
    void getDMARC() {
        Optional<DMARCResult> optionalDMARCResult = DMARCChecker.getDMARC("rpcnet.net");

        assertTrue(optionalDMARCResult.isPresent());

        DMARCResult dmarcResult = optionalDMARCResult.get();

        assertTrue(dmarcResult.getVersion().isPresent());
        assertEquals("DMARC1", dmarcResult.getVersion().get());
        assertTrue(dmarcResult.getPercentage().isPresent());
        assertEquals("100", dmarcResult.getPercentage().get());
        assertTrue(dmarcResult.getForensicReport().isPresent());
        assertEquals("mailto:webmaster@rpcnet.net", dmarcResult.getForensicReport().get());
        assertTrue(dmarcResult.getAggregateReport().isPresent());
        assertEquals("mailto:webmaster@rpcnet.net", dmarcResult.getAggregateReport().get());
        assertTrue(dmarcResult.getPolicy().isPresent());
        assertEquals("quarantine", dmarcResult.getPolicy().get());
        assertTrue(dmarcResult.getSubdomainsPolicy().isPresent());
        assertEquals("reject", dmarcResult.getSubdomainsPolicy().get());
        assertTrue(dmarcResult.getDomainKeysAlignment().isPresent());
        assertEquals("s", dmarcResult.getDomainKeysAlignment().get());
        assertTrue(dmarcResult.getSPFAlignment().isPresent());
        assertEquals("s", dmarcResult.getSPFAlignment().get());
        assertTrue(dmarcResult.getReportFormat().isPresent());
        assertEquals("afrf", dmarcResult.getReportFormat().get());
        assertTrue(dmarcResult.getAggregateReportTimeInterval().isPresent());
        assertEquals("86400", dmarcResult.getAggregateReportTimeInterval().get());
        assertTrue(dmarcResult.getForensicReportingOptions().isPresent());
        assertEquals("1", dmarcResult.getForensicReportingOptions().get());

    }
}