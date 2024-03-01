# enccat - Writeup

* Convert the APK to a JAR file:
```shell
$ dex2jar -o enccat.jar enccat.apk
```

* Convert the JAR to a ZIP:
```shell
mv enccat.jar enccat.zip
```

* Unzip ZIP:
```shell
unzip enccat.zip
```

* Decompile `de/uni_luebeck/its/ctf/enccat/Login.class`
```shell
jd-gui Login.class
```

* Use decompiled code as basis to decrypt the flag
```shell
javac Solve.java
java Solve
```

