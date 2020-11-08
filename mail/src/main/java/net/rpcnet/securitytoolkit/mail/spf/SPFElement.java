package net.rpcnet.securitytoolkit.mail.spf;

import org.immutables.value.Value;

@Value.Immutable
public interface SPFElement {

    SPFQualifier getQualifier();
    String getName();

}
