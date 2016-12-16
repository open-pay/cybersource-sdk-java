package com.cybersource.ws.client;

import java.io.File;

public interface KeyFileLoader {

    boolean isTemporary();

    File getFile(String filename);

}
