**WARNING: This plugin is in very early stages of development. It works
for us, but might not be robust enough for your purposes. Please test
it thoroughly before using it in production environments.**


This passwdqc plugin verifies password strength using a passwdqc
policy when there is a LDAP Password Modify Extended Operation.

This is a plugin for the 389 directory server, version 1.2.11. It
might work with other versions, but it was not tested.

The 389 directory server can be found at: http://www.port389.org
The passwdqc toolset can be found at: http://www.openwall.com/passwdqc


#### BUILD

You'll need the devel-packages of the slapi header files and passwdqc.
In fedora these are 389-ds-base-devel and passwdqc-devel respectively.

The following should work on a standard linux installation:

```
$ ./configure --prefix=/usr --libdir=/usr/lib64 \
              --with-nspr-inc=/usr/include/nspr4 \
              --with-ds-inc=/usr/include/dirsrv
$ make
$ make install
```

#### INSTALL

1. Copy the libpasswdqc-plugin.so file to <ds-base>/lib/dirserv/plugins/
2. Copy the plugin configuration schema schema/50passwdqc-plugin.ldif to
   the server schemas directory (usually /etc/dirsrv/<slapd-dir>/schema).
3. Configure the plugin, by adding the provided passwdqc-conf.ldif
   into the server dse.ldif.
3. The passwdqcParam attribute is used for passwdqc configuration, one
   attribute for each parameter. For example,
```
     passwdqcParam: min=disabled,disabled,disabled,disabled,8
     passwdqcParam: max=8
     passwdqcParam: passphrase=0
```
   Passwdqc defaults are used if a parameter is not specified. Please
   see passwdqc documentation for more details.
