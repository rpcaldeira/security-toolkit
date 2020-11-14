package net.rpcnet.securitytoolkit.common.dns.interfaces;

import org.immutables.value.Value;

@Value.Immutable
public interface WrapperCAADto {
    String getValue();
    int getFlags();
    String getTag();
}
