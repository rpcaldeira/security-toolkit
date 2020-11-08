package net.rpcnet.securitytoolkit.mail.spf;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SPFCheckerTest {

    @Test
    void getSPF() {
        System.out.println(SPFChecker.getSPF("rpcnet.net"));
    }
}