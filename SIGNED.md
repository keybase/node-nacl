##### Signed by https://keybase.io/max
```
-----BEGIN PGP SIGNATURE-----
Comment: GPGTools - https://gpgtools.org

iQIcBAABCgAGBQJVWU5LAAoJEGBSsq0xpmMc3MwQAJsyEOcl200+MXqTeOOT4lXM
Rf9WzQjJI/6sFM6ZbZlQ5+xjI1IRMM49JJC0OL4nCP2WPrOhktGF2IJNnHcfcKvv
YUjyDQdwLHSuV04SejdDjYIqP9dDhAMOuSulRawr9xt3I3jw0w5Hpq+AIDbAuKxQ
KJUqOU/kqDIovn/fILXLUPEgYpTExL8HOjeAafh/Yymw+1riyvksZXwNeLV2WIhY
3OqeoMbYNaqEULiC9olbvGvg2Cu7aF3R0oM9SLZLsxmWCWjagdklxQpbfSQhGVzh
iuJ3Ma/oak0Qvrpf4M0j98EGFIvxQimMjaxstW7YSorEjgqiXHRncHa1xv+Usl2z
5//fDxdDhpqlJV7+iIqfHU2tS0hGERxdhngdU3ZeZo8M9RLocPmfW9hjxR2M0lVM
SeOZeTyzL0/eagTCGxiYEodtjsX8sAf4Tz6LkqKNkDjSXz1w7nORIP3SGy6fYw1x
C7Sputlv8vhJJ08hp46Y2PRbcfDeYc+i/eIkS1El2xzQer1CIsZJujhKOlSF0jHR
SmS8j3TIlG1nsNSzUq+J7pARxmeNk2/wJgIR49uMuVIYZ5zKu9CFxv6lqhinUiX+
QUtklbIywuD1uaw/C6gCVw3sY/riAwJKtJ6LRXln0IDRVL2mQeYFMiS6k4Eh6ASr
Yc6lrfew8atvJMMXUkiK
=GHc+
-----END PGP SIGNATURE-----

```

<!-- END SIGNATURES -->

### Begin signed statement 

#### Expect

```
size    exec  file                contents                                                        
              ./                                                                                  
46              .gitignore        e446248bb7d6e5c58234de6c127ee27687b1d84304f84bd5f368b4280b0e92db
1475            LICENSE           f8bc12c174a5377c5d2e96c2a9c419ff7b608459bb7615fc305661eca155384d
1135            Makefile          949e832fcffda80cc6f45c8e7e977a08485fc84a5e0ee83ac0edad4582da3426
94              README.md         6d45790af19c47d5b2df93405a8a78179913860177841171e1224ed897120f06
                lib/                                                                              
936               base.js         32741386a25d562b714b247078c916ed925b7209495a76c164bac0e99d24eed5
1035              main.js         40e30e62fa1f55ec831707849476953c998bce89b740f5b08347c0217853a220
2067              sodium.js       49c3469abd276df579e045ccc17c49253630b3e9e26b73e88ed9eec692f209f5
2075              tweetnacl.js    d4da18bf492da3e923890b04659d7c672d0971ec028d9bb7ecca8ec1ea0aa8a1
645               util.js         be2846c96d0fdcd07dd96c86fcb529af94e09ba8d9110ee6b47d433fbef2a963
794             package.json      7efbb8829a3fd39aa78e1a09189d2c283f32292884b34613805958d2d6a72f58
                src/                                                                              
1400              base.iced       71a5c89cb57ff4bc1964910d987f1d914ff9f02e3058438c6a660040024c7530
1240              main.iced       4a18d5ff187661417b5fba4d1b6517bd5d2337022e9d41c396921ac3a278ed52
1828              sodium.iced     6147b59cc4c0b015b9b5e1eb3340e30bfc232a9aacd1cb4b1b1380b36cb3e733
2019              tweetnacl.iced  4f845affac187a3b01eccadf33494f8a10a3aa7b013456f976afd6219c097703
376               util.iced       8ae5f3a21f115c41d4ac72420d945cde81683d8690094a440d6dd00572fc7755
                test/                                                                             
                  browser/                                                                        
287                 index.html    e31387cfd94034901e89af59f0ad29a3e2f494eb7269f1806e757be21b3cf33e
193                 main.iced     ba58653bd3407fbaf8237ec01c61668fb0c567d113eed01fb862e946a39000de
670290              test.js       96b738bbc33f0ab9d1a13cbaaca6f81d1713f90662ae238ac77038d0d377378a
                  files/                                                                          
2320                0_sigs.iced   f980c55498dafccb45bc3ebe5af21d7be46c110cbec022fe2eda9d46e192760e
52                run.iced        8e58458d6f5d0973dbb15d096e5366492add708f3123812b8e65d49a685de71c
```

#### Ignore

```
/SIGNED.md
```

#### Presets

```
git      # ignore .git and anything as described by .gitignore files
dropbox  # ignore .dropbox-cache and other Dropbox-related files    
kb       # ignore anything as described by .kbignore files          
```

<!-- summarize version = 0.0.9 -->

### End signed statement

<hr>

#### Notes

With keybase you can sign any directory's contents, whether it's a git repo,
source code distribution, or a personal documents folder. It aims to replace the drudgery of:

  1. comparing a zipped file to a detached statement
  2. downloading a public key
  3. confirming it is in fact the author's by reviewing public statements they've made, using it

All in one simple command:

```bash
keybase dir verify
```

There are lots of options, including assertions for automating your checks.

For more info, check out https://keybase.io/docs/command_line/code_signing