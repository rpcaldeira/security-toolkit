package net.rpcnet.securitytoolkit.mail.spf;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SPFCheckerTest {

    public static final String SPF_GOOGLE_COM = "_spf.google.com";
    public static final String RPCNET_NET = "rpcnet.net";

    @Test
    void getSPF() {
        Optional<SPFResult> spf = SPFChecker.getSPF(RPCNET_NET);
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