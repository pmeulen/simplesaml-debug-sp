simplesaml-debug-sp
===================

A SimpleSAMLphp application for testing SAML SP functionality

To install:
* Configure the default-sp in simpleSAMLphp as a hosted SP (http://simplesamlphp.org/docs/stable/saml:sp)
* Put sp-debug.php in the simplesamlphp/www directory
* Put saml2keeper in the simplesamlphp/modules directory
* Enable the saml2keeper module: touch simplesamlphp/modules/saml2keeper/enable

Use the script by pointing your browser to the sp-debug.php script 
