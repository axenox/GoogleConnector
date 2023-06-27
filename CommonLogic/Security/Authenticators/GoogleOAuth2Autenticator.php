<?php
namespace axenox\GoogleConnector\CommonLogic\Security\Authenticators;

use axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Authenticator;
use League\OAuth2\Client\Token\AccessTokenInterface;

/**
 * Authenticates users via Google Single-Sign-On (OAuth 2.0).
 * 
 * To enable Single-Sign-On with Google, you will need to register the workbench at
 * Google APIs: https://console.developers.google.com/apis/credentials.
 * 
 * After the app registration is complete, proceed to "Credentials" inside the app settings
 * on Google and create an OAuth 2.0 client id of type "web application". When asket for
 * URLs use
 * 
 * - The root URL of the workbench installation as "Authorized JavaScript origins" 
 * (or `http://localhost` for testing purposes)
 * - `http://yoururl/api/oauth2client` as "Authorized redirect URIs" 
 * (or `http://localhost/workbench/api/oauth2client` for testing) 
 * 
 * Now Google will generate the `client_id` and the `client_secret` needed to configure the 
 * authenticator.
 * 
 * ## Example Configuration
 * 
 * ```
 *  {
 *      "class": "\\axenox\\GoogleConnector\\CommonLogic\\Security\\Authenticators\\GoogleOAuth2Autenticator",
 *      "name": "via Google",
 *      "id": "OAUTH_GOOGLE",
 *      "client_id": "914683922990-m5mani2914raaaalb7spoob1b8k4ktko.apps.googleusercontent.com",
 *      "client_secret": "-piYBNdIBYQnQIcZX_CniNml"
 *      "create_new_users": true,
 *      "create_new_users_with_roles": [
 *          "exface.Core.SUPERUSER"
 *      ]
 *  }
 * 
 * ```
 *
 * @author Andrej Kabachnik
 *
 */
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