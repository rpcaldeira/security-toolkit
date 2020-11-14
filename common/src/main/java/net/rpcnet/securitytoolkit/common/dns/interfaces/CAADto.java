package net.rpcnet.securitytoolkit.common.dns.interfaces;

import org.immutables.value.Value;

@Value.Immutable
public interface CAADto {
    String getValue();
    int getFlags();
    String getTag();
}
