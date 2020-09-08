package net.rpcnet.securitytoolkit.mail.dmarc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DMARCCheckerTest {

    @Test
    void getDMARC() {
        System.out.println(DMARCChecker.getDMARC("rpcnet.net"));
    }
}