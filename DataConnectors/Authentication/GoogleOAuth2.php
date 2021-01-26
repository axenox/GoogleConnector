<?php
namespace axenox\GoogleConnector\DataConnectors\Authentication;

use axenox\OAuth2Connector\DataConnectors\Authentication\OAuth2;
use axenox\GoogleConnector\CommonLogic\Security\Authenticators\GoogleOAuth2Trait;

class GoogleOAuth2 extends OAuth2
{
    use GoogleOAuth2Trait;
}