package net.rpcnet.securitytoolkit.mail.dmarc;

import org.immutables.value.Value;

@Value.Immutable
public abstract class DMARCResult {

    abstract String getVersion();

}
