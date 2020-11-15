package net.rpcnet.securitytoolkit.dns.zonetransfer;

import net.rpcnet.securitytoolkit.common.dns.interfaces.IDNSResolverWrapper;
import net.rpcnet.securitytoolkit.common.dns.wrapper.DNSResolverWrapper;

public class ZoneTransferChecker {

    private final IDNSResolverWrapper dnsResolverWrapper;

    public ZoneTransferChecker(){
        this.dnsResolverWrapper = new DNSResolverWrapper();
    }

    public ZoneTransferChecker(IDNSResolverWrapper dnsResolverWrapper){
        this.dnsResolverWrapper = dnsResolverWrapper;
    }

    public boolean checkZoneTransfer(String domain){
        return dnsResolverWrapper.getAXFR(domain);
    }

}
