package net.rpcnet.securitytoolkit.mail.dmarc;

import net.rpcnet.securitytoolkit.common.dns.RecordChecker;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DMARCCheckerTest {

    private static final String DOMAIN = "rpcnet.net";
    private static final String DMARC_STRING = "v=DMARC1;p=quarantine;sp=reject;adkim=s;aspf=s;pct=100;fo=1;rf=afrf;ri=86400;rua=mailto:webmaster@rpcnet.net;ruf=mailto:webmaster@rpcnet.net";
    private DMARCChecker dmarcChecker;

    @BeforeAll
    public void setUp(){

        List<String> result = Collections.singletonList(DMARC_STRING);
        RecordChecker recordChecker = mock(RecordChecker.class);
        when(recordChecker.getTXT(anyString(), eq(DOMAIN))).thenReturn(result);

        dmarcChecker = new DMARCChecker(recordChecker);
    }

    @Test
    void getDMARC() {
        Optional<DMARCResult> optionalDMARCResult = dmarcChecker.getDMARC(DOMAIN);

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