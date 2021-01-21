<?php
namespace axenox\GoogleConnector\CommonLogic\Security\Authenticators;

use axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Authenticator;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use axenox\GoogleConnector\CommonLogic\Security\Authenticators\GoogleOAuth2Trait;

class GoogleOAuth2Autenticator extends OAuth2Authenticator
{
    use GoogleOAuth2Trait;
    
    protected function getNameDefault(): string
    {
        return 'Google';
    }
}