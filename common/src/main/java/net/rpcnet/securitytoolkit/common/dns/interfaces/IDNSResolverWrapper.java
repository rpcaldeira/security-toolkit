package net.rpcnet.securitytoolkit.common.dns.interfaces;

import java.util.Collection;

public interface IDNSResolverWrapper {
    Collection<String> getTXT(String format, String domain);

    Collection<WrapperCAADto> getCAA(String format, String domain);

    boolean getAXFR(String domain);
}
