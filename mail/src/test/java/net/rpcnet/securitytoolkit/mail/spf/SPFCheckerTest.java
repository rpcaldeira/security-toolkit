package net.rpcnet.securitytoolkit.mail.spf;

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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SPFCheckerTest {

    private static final String SPF_GOOGLE_COM = "_spf.google.com";
    private static final String DOMAIN = "rpcnet.net";
    private static final String SPF_STRING = "v=spf1 +mx +include:_spf.google.com -all";

    private SPFChecker spfChecker;

    @BeforeAll
    public void setUp(){
        List<String> result = Collections.singletonList(SPF_STRING);

        RecordChecker recordChecker = mock(RecordChecker.class);
        when(recordChecker.getTXT(DOMAIN)).thenReturn(result);

        spfChecker = new SPFChecker(recordChecker);
    }

    @Test
    void getSPF() {
        Optional<SPFResult> spf = spfChecker.getSPF(DOMAIN);
        assertTrue(spf.isPresent());
        SPFResult spfResult = spf.get();

        assertEquals(Optional.of(SPFQualifier.FAIL), spfResult.getAllQualifier());
        assertEquals(Optional.empty(), spfResult.getAQualifier());
        assertEquals(Collections.singletonList(ImmutableSPFElement.builder().qualifier(SPFQualifier.PASS).value(SPF_GOOGLE_COM).build()), spfResult.getIncludeRecords());
        assertEquals(Optional.of(SPFQualifier.PASS), spfResult.getMailExchangeQualifier());
        assertEquals(Optional.of(1), spfResult.getVersion());
        assertEquals(Collections.emptyList(), spfResult.getIp4Records());
        assertEquals(Collections.emptyList(), spfResult.getIp6Records());
    }
}