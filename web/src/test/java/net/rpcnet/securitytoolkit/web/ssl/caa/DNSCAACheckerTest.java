package net.rpcnet.securitytoolkit.web.ssl.caa;

import org.junit.jupiter.api.Test;

import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;

class DNSCAACheckerTest {

    @Test
    void checkDNSCAA() {
        Collection<CAAResult> caaResults = DNSCAAChecker.checkDNSCAA("rpcnet.net");

        assertEquals(1, caaResults.size());
        CAAResult caaResult = caaResults.stream().findFirst().orElse(null);

        assertNotNull(caaResult);
        assertTrue(caaResult.getFlags().isPresent());
        assertEquals(1, caaResult.getFlags().get());
        assertTrue(caaResult.getTag().isPresent());
        assertEquals("issue", caaResult.getTag().get());
        assertTrue(caaResult.getValue().isPresent());
        assertEquals("comodoca.com", caaResult.getValue().get());
    }
}