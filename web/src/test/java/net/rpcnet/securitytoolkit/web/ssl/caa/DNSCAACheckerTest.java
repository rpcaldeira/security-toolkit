package net.rpcnet.securitytoolkit.web.ssl.caa;

import net.rpcnet.securitytoolkit.common.dns.RecordChecker;
import net.rpcnet.securitytoolkit.common.dns.interfaces.CAADto;
import net.rpcnet.securitytoolkit.common.dns.interfaces.ImmutableCAADto;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DNSCAACheckerTest {

    private static final String DOMAIN = "rpcnet.net";
    private static final String VALUE = "comodoca.com";
    private static final String ISSUE = "issue";
    private static final int FLAGS = 1;

    private DNSCAAChecker dnscaaChecker;

    @BeforeAll
    public void setUp(){
        List<CAADto> caaDto = List.of(ImmutableCAADto.builder().value(VALUE).tag(ISSUE).flags(FLAGS).build());

        RecordChecker recordChecker = mock(RecordChecker.class);
        when(recordChecker.getCAA(DOMAIN)).thenReturn(caaDto);

        dnscaaChecker = new DNSCAAChecker(recordChecker);
    }

    @Test
    void checkDNSCAA() {
        Collection<CAAResult> caaResults = dnscaaChecker.checkDNSCAA(DOMAIN);

        assertEquals(1, caaResults.size());
        CAAResult caaResult = caaResults.stream().findFirst().orElse(null);

        assertNotNull(caaResult);
        assertTrue(caaResult.getFlags().isPresent());
        assertEquals(FLAGS, caaResult.getFlags().get());
        assertTrue(caaResult.getTag().isPresent());
        assertEquals(ISSUE, caaResult.getTag().get());
        assertTrue(caaResult.getValue().isPresent());
        assertEquals(VALUE, caaResult.getValue().get());
    }
}