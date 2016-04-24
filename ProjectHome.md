`OpenDirectoryAuth` is a python module that provides authentication feature to python under OS X.

Using it is as simple as:
```
>>> import OpenDirectoryAuth
>>> OpenDirectoryAuth.authenticate('Teo', 'valid_password')
True
>>> OpenDirectoryAuth.authenticate('Teo', 'invalid_password')
False
```

You need to compile it with Xcode for your plataform and python version.

This is just a wrapper for [this sample code by apple](http://devworld.apple.com/samplecode/CryptNoMore/)