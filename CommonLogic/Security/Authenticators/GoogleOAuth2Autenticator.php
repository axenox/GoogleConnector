<?php
namespace axenox\GoogleConnector\CommonLogic\Security\Authenticators;

use axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Authenticator;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use axenox\GoogleConnector\CommonLogic\Security\Authenticators\GoogleOAuth2Trait;
use League\OAuth2\Client\Token\AccessTokenInterface;

class GoogleOAuth2Autenticator extends OAuth2Authenticator
{
    use GoogleOAuth2Trait;
    
    /**
     *
     * {@inheritdoc}
     * @see OAuth2Authenticator::getNameDefault()
     */
    protected function getNameDefault(): string
    {
        return 'via Google';
    }
    
    /**
     * 
     * {@inheritdoc}
     * @see OAuth2Authenticator::getNewUserData()
     */
    protected function getNewUserData(AccessTokenInterface $token) : array
    {
        /* @var $ownerDetails \League\OAuth2\Client\Provider\GoogleUser */
        $ownerDetails = $this->getOAuthProvider()->getResourceOwner($token);
        $data = [
            'FIRST_NAME' => $ownerDetails->getFirstName(),
            'LAST_NAME' => $ownerDetails->getLastName(),
            'EMAIL' => $ownerDetails->getEmail()
        ];
        
        if ($locale = $ownerDetails->getLocale()) {
            $data['LOCALE'] = $locale;
        }
        
        return $data;
    }
}