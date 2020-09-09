package net.rpcnet.securitytoolkit.web.ssl.caa;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DNSCAACheckerTest {

    @Test
    void checkDNSCAA() {
        DNSCAAChecker.checkDNSCAA("rpcnet.net");
    }
}