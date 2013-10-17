<?php

/* sspmod_saml2keeper_SAML2Keeper - Module that saves the SAMLResponse in the simplesaml session
 * so it can be accessed later.
 *
 * To use:
 * - Enable the module: touch simplesamlphp/modules/saml2keeper/enable
 * - Before authentication set the return URL
 * - Set ReturnCallback to sspmod_saml2keeper_SAML2Keeper::loginCallback

$as = new SimpleSAML_Auth_Simple('default-sp');
$session = SimpleSAML_Session::getInstance();
$session->setData('string', 'SAML2Keeper_ReturnTo', $returnURL);    // URL to return to after authentication
$as->login( array(
    //'ReturnTo' => '...', // Setting a ReturnTo will override (disable) ReturnCallback
    'ReturnCallback' => array('sspmod_saml2keeper_SAML2Keeper','loginCallback'),
) );


* To get the SAMLResponse after authentication:

$SAMLResponse = base64_decode( $session->getData('string', 'SAML2Keeper_SAMLResponse') );
$document = new DOMDocument();
$document->loadXML($SAMLResponse);
$xml = $document->firstChild;
...

 */

// Autoloadable class
class sspmod_saml2keeper_SAML2Keeper {
    static function LoginCallback($state) {

        /** @var $session SimpleSAML_Session **/
        $session = SimpleSAML_Session::getInstance();

        $return = $session->getData('string', 'SAML2Keeper_ReturnTo');
        if (NULL === $return)
        {
            SimpleSAML_Logger::error('Missing required SAML2Keeper_ReturnTo session variable');
            SimpleSAML_Logger::notice('Hint: Use SimpleSAML_Session::setData("string", "SAML2Keeper_ReturnTo", $ReturnToURL)');
        }

        // Safe SAMLResponse if it is set
        if (isset($_REQUEST['SAMLResponse']))
            $session->setData('string', 'SAML2Keeper_SAMLResponse', $_REQUEST['SAMLResponse']);

        SimpleSAML_Utilities::redirect($return);
    }
}

