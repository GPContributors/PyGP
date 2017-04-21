# PyGP

PyGP is a open source python **globalplatform** client library. 
Using this library, you can use all features of GlobalPlatform project use Python programming language.

It supports Python 3.5+.

.. code-block:: pycon

    >>> from pygp import *
    >>> # Starting script
    >>> terminal()
    >>> select("A0 00 00 01 51 00 00 00")
    >>> auth(keysetversion = '31', securitylevel = SECURITY_LEVEL_NO_SECURE_MESSAGING)
    

You can find more information in the `documentation`_.



.. _`documentation`: https://pygp.io/
.. _`issue tracker`: https://github.com/GPContributors/PyGP//issues
