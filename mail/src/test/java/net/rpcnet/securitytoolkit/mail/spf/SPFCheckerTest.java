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

        assertEquals(Optional.of(SPFQualifier.FAIL), spfResult.getAll());
        assertEquals(Collections.emptyList(), spfResult.getARecord());
        assertEquals(Collections.singletonList(ImmutableSPFElement.builder().qualifier(SPFQualifier.PASS).value(SPF_GOOGLE_COM).build()), spfResult.getInclude());
        assertEquals(Optional.of(SPFQualifier.PASS), spfResult.getMailExchange());
        assertEquals(Optional.of(1), spfResult.getVersion());
    }
}