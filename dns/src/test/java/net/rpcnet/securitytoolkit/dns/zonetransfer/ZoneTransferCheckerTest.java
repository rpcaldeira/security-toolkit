package net.rpcnet.securitytoolkit.dns.zonetransfer;

import net.rpcnet.securitytoolkit.common.dns.wrapper.DNSResolverWrapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ZoneTransferCheckerTest {

    private ZoneTransferChecker zoneTransferChecker;

    @BeforeAll
    public void setUp(){
        zoneTransferChecker = new ZoneTransferChecker(new DNSResolverWrapper());
    }

    @Test
    void getZoneTransfer() {
        zoneTransferChecker.checkZoneTransfer("rpcnet.net");
    }

}