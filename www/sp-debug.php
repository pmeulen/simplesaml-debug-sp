<?php

require_once('../lib/_autoload.php');


function XMLTextNode2HTML_TS($domnode)
{
    if (!is_null($domnode) && isset($domnode[0])) {
        $time = SimpleSAML_Utilities::parseSAML2Time($domnode[0]->textContent);
        $offset = $time - time();
        $str = '<b>'.gmdate('r', $time).'</b>';
        $str .= ' (now '. (($offset>0) ? '+':'') . round(($offset/60)) . ' minutes)';
        return $str;
    }

    return '<i>N/A</i>';
}

function XMLTextNode2HTML($domnode)
{
    if (!is_null($domnode) && isset($domnode[0])) {
        return '<b>'.htmlentities($domnode[0]->textContent).'</b>';
    }

    return '<i>N/A</i>';
}

$gLOAmap = array(
    1 => 'http://suaas.example.com/assurance/loa1',
    2 => 'http://suaas.example.com/assurance/loa2',
    3 => 'http://suaas.example.com/assurance/loa3',
);


// MAIN

$as = new SimpleSAML_Auth_Simple('default-sp');

$session = SimpleSAML_Session::getInstance();

$bIsAuthenticated = $as->isAuthenticated();

// Build return URL. This is where ask simplesamlPHP to direct the browser to after login or logout
// Point to this script, but without any request parameters so we won't trigger an login again (and again, and again, and ...)
$returnURL = ($_SERVER['HTTPS'] == 'on') ? 'https://' : 'http://';
$returnURL .= $_SERVER['HTTP_HOST'];
$returnURL .= $_SERVER['SCRIPT_NAME'];

// Process login and logout actions. Neither login nor logout return
if (isset($_REQUEST['action']) && $_REQUEST['action'] == 'login' ) {

    // Unset existing RequiredAuthnContextClassRef first
    $session->deleteData('string', 'RequiredAuthnContextClassRef');
    $bForceAuthn = false;
    if ( (isset($_REQUEST['forceauthn'])) && ($_REQUEST['forceauthn'] == 'true') )
        $bForceAuthn = true;

    // For use by SAML2Keeper callback function
    $session->setData('string', 'SAML2Keeper_ReturnTo', $returnURL);

    // login
    if ( !isset($_REQUEST['loa']) || !isset($gLOAmap[$_REQUEST['loa']]) ) {
        $as->login( array(
            //'ReturnTo' => $returnURL,
            'ReturnCallback' => array('sspmod_saml2keeper_SAML2Keeper','loginCallback'),
            'ForceAuthn' => $bForceAuthn,
        ) );   // Vanilla login without specifying a LOA
    }
    else {
        // Store the requested LOA in the session so we can verify it later
        $session->setData('string', 'RequiredAuthnContextClassRef', $gLOAmap[$_REQUEST['loa']]);

        $as->login( array(
            //'ReturnTo' => $returnURL,
            'ReturnCallback' => array('sspmod_saml2keeper_SAML2Keeper','loginCallback'),
            'ForceAuthn' => $bForceAuthn,
            'saml:AuthnContextClassRef' => $gLOAmap[$_REQUEST['loa']]  // Specify LOA
        ) );
    }

    // $as->requireAuth(array('saml:idp' => 'wayf-test.surfnet.nl') );
    exit;   // Added for clarity

}

if( isset($_REQUEST['action']) && $_REQUEST['action'] == 'logout' ) {
    $as->logout( array (
        'ReturnTo' => $returnURL,
    ) );  // Process logout
    exit;   // Added for clarity
}

// Display page

echo <<<head
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
	<head>
		<meta http-equiv="Content-type" content="text/html;charset=UTF-8" />
		<style type="text/css">
		    table,th,td {border: 1px solid black;}
		    th,td {padding 1px}
        </style>
		<title>simpleSAMLphp Demo</title>
	</head>
	<body>
		<h1>simpleSAMLphp Demo</h1>
head;

if ( $bIsAuthenticated ) {
    $attributes = $as->getAttributes();

    /** @var $session SimpleSAML_Session */
    $requestedLOA = $session->getData('string', 'RequiredAuthnContextClassRef');
    $authState = $session->getAuthState();
    $actualLOA = $authState['saml:sp:AuthnContext'];
    $nameID = $session->getNameID();
    $authnInstant = gmdate('r', $authState['AuthnInstant'] );
    $expire = gmdate('r', $authState['Expire'] );

    echo <<<html
        <h2>You are logged in</h2>
html;

    echo "<h3>LOA</h3>";
    echo "<p>Actual LOA is: <b>{$actualLOA}</b></p>";
    if (NULL !== $requestedLOA) {
        echo "<p>Requested LOA was: <b>{$requestedLOA}</b></p>";
    }

    echo <<<html
    <h3>NameID</h3>
    <table>
        <tr><th>Value</th><td>{$nameID['Value']}</td></tr>
        <tr><th>Format</th><td>{$nameID['Format']}</td></tr>
    </table>
html;


    echo <<<html
        <h3>Attributes</h3>
        <table>
        	<tr><th>Attribute</th><th>Value(s)</th></tr>
html;

    foreach ($attributes as $attrName => $attrVal) {
        echo "<tr><td>{$attrName}</td><td>";
        if (is_array($attrVal))
            echo implode('<br />', $attrVal);
        else
            echo $attrVal;
        echo "</td>";
    }
    echo <<<html
        </table>
        <h3>Logout</h3>
        <p>
            <form name="logout" action="{$$returnURL}" method="get">
               <input type="hidden" name="action" value="logout"/>
               <input type="submit" value="Logout" />
            </form>
        </p>

	<h3>Session</h3>
	<p>
	    SimpleSAMLphp session start: <b>{$authnInstant}</b></br />
            SimpleSAMLphp session expire: <b>{$expire}</b>
        </p>
html;
} else {
    echo <<<html
        <h2>Your are not logged in</h2>
html;
}

echo <<<html
        <h3>Login (again)</h3>
        <p>
            <form name="login" action="{$returnURL}" method="get">
               <input type="hidden" name="action" value="login"/>
               <p>Request LOA:<br />
                   <input type="radio" name="loa" value="1" />1<br />
                   <input type="radio" name="loa" value="2" />2<br />
                   <input type="radio" name="loa" value="3" />3<br />
                   <a href="javascript:{}" onclick="Array.prototype.map.call(document.getElementsByName('loa'), function(e){e.checked=false});">None</a><br />
               </p>
               <p>
                    <input type="checkbox" name="forceauthn" value="true" />Force authentication<br />
               </p>
               <p>
                    <input type="submit" value="Login" />
               </p>
            </form>
        </p>
html;

$SAMLResponse = $session->getData('string', 'SAML2Keeper_SAMLResponse');
if ($SAMLResponse)
{
    echo '<h3>SAMLResponse</h3>';
    $SAMLResponse = base64_decode($SAMLResponse);
    if (false !== $SAMLResponse)
    {
        $document = new DOMDocument();
        $document->loadXML($SAMLResponse);
        $xml = $document->firstChild;

        //$msg = new SAML2_Response($xml);
        $response_IssueInstant = SAML2_Utils::xpQuery($xml, '/saml_protocol:Response/@IssueInstant');
        $assertion_IssueInstant = SAML2_Utils::xpQuery($xml, '/saml_protocol:Response/saml_assertion:Assertion/@IssueInstant');
        $condition_NotBefore = SAML2_Utils::xpQuery($xml, '/saml_protocol:Response/saml_assertion:Assertion/saml_assertion:Conditions/@NotBefore');
        $condition_NotOnOrAfter = SAML2_Utils::xpQuery($xml, '/saml_protocol:Response/saml_assertion:Assertion/saml_assertion:Conditions/@NotOnOrAfter');
        $audience_Restriction = SAML2_Utils::xpQuery($xml, '/saml_protocol:Response/saml_assertion:Assertion/saml_assertion:Conditions/saml_assertion:AudienceRestriction/saml:Audience');
        $assertion_AuthnInstant = SAML2_Utils::xpQuery($xml, '/saml_protocol:Response/saml_assertion:Assertion/saml_assertion:AuthnStatement/@AuthnInstant');
        $SessionNotOnOrAfter = SAML2_Utils::xpQuery($xml, '/saml_protocol:Response/saml_assertion:Assertion/saml_assertion:AuthnStatement/@SessionNotOnOrAfter');
        $SessionIndex = SAML2_Utils::xpQuery($xml, '/saml_protocol:Response/saml_assertion:Assertion/saml_assertion:AuthnStatement/@SessionIndex' );
        echo "<h4>Response</h4>";
        echo "IssueInstant: ".XMLTextNode2HTML_TS($response_IssueInstant)."<br />";
        echo "<h4>Assertion</h4>";
        echo "IssueInstant: ".XMLTextNode2HTML_TS($assertion_IssueInstant)."<br />";
        echo "Condition NotBefore: ".XMLTextNode2HTML_TS($condition_NotBefore)."<br />";
        echo "Condition NotOnOrAfter: ".XMLTextNode2HTML_TS($condition_NotOnOrAfter)."<br />";
        echo "AudienceRestriction: ".XMLTextNode2HTML($audience_Restriction)."<br />";
        echo "AuthnInstant: ".XMLTextNode2HTML_TS($assertion_AuthnInstant)."<br />";
        echo "SessionNotOnOrAfter: ".XMLTextNode2HTML_TS($SessionNotOnOrAfter)."<br />";
        echo "SessionIndex: ".XMLTextNode2HTML($SessionIndex)."<br />";
        echo '<pre>';
        echo htmlentities($SAMLResponse);
        echo '</pre>';
    }
    else
    {
        echo 'Error decoding SAMLResponse (invalid base64)<br />';
    }
}

echo <<<html
    </body>
</html>
html;

