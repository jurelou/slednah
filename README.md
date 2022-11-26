# Get windows handles

## Usage

```
make ; .\slednah.exe
```

# TODO

- SeDebugPrivilege
- NtQueryObject timeout (mettre dans un thread avec futures qui timeout au bout d'1 seconde)

- utiliser GetFileInformationByHandleEx  pour récupérer le nom de fichier
    - https://github.com/scottlundgren/objects/blob/master/objects/objects/objects.cpp#L314
    - https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex
- ou: https://learn.microsoft.com/fr-fr/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlea