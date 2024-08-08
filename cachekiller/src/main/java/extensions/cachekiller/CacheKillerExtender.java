package extensions.cachekiller;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;


public class CacheKillerExtender implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("CacheKiller");
        api.userInterface().registerContextMenuItemsProvider((new CacheKiller(api)));
    }
}