simplesaml-debug-sp
===================

A SimpleSAMLphp application for testing SAML SP functionality: force authentication, scoping, request signing, RequesterID. The included "saml2keeper" module is used to display SAML response received from the identity provider.

To install:
* Configure the "default-sp" in simpleSAMLphp as a hosted SP by following the instructions at http://simplesamlphp.org/docs/stable/saml:sp
* Put sp-debug.php in the simplesamlphp/www directory
* Put saml2keeper in the simplesamlphp/modules directory
* Enable the saml2keeper module: `touch simplesamlphp/modules/saml2keeper/enable`

Use the script by pointing your browser to the sp-debug.php script 
