<?php
namespace axenox\GoogleConnector\CommonLogic\Security\Authenticators;

use exface\Core\Interfaces\WidgetInterface;
use exface\Core\Interfaces\Widgets\iContainOtherWidgets;
use exface\Core\CommonLogic\UxonObject;
use exface\Core\Interfaces\Security\AuthenticationProviderInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Google;
use exface\Core\Factories\WidgetFactory;
use axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2AuthenticatedToken;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use axenox\OAuth2Connector\Exceptions\OAuthHttpException;
use exface\Core\Exceptions\Security\AuthenticationFailedError;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use League\OAuth2\Client\Token\AccessTokenInterface;
use exface\Core\Exceptions\Security\AuthenticatorConfigError;

trait GoogleOAuth2Trait
{
    use OAuth2Trait;
    
    private $provider = null;
    
    private $accessType = 'offline';
    
    protected function exchangeOAuthToken(AuthenticationTokenInterface $token): OAuth2AuthenticatedToken
    {
        if ($token instanceof OAuth2AuthenticatedToken) {
            if ($token->getAccessToken()->hasExpired()) {
                throw new AuthenticationFailedError($this->getAuthProvider(), 'OAuth token expired: Please sign in again!');
            } else {
                return $token;
            }
        }
        
        if (! $token instanceof OAuth2RequestToken) {
            throw new AuthenticationRuntimeError($this, 'Cannot use "' . get_class($token) . '" as OAuth token!');
        }
        
        $clientFacade = $this->getOAuthClientFacade();
        $request = $token->getRequest();
        $requestParams = $request->getQueryParams();
        $provider = $this->getOAuthProvider();
        
        switch (true) {
            
            // If we are not processing a provider response, either use the stored token
            // or redirect ot the provider to start authentication
            case empty($requestParams['code']):
                
                $authOptions = [];
                $oauthToken = $this->getTokenStored();
                if ($oauthToken) {
                    $expired = $oauthToken->hasExpired();
                    if ($expired) {
                        if (! $this->getRefreshToken($oauthToken)) {
                            $authOptions = ['prompt' => 'consent'];
                        } else {
                            $oauthToken = $provider->getAccessToken('refresh_token', [
                                'refresh_token' => $this->getRefreshToken($oauthToken)
                            ]);
                        }
                    }
                }
                if (! $oauthToken || ! empty($authOptions)) {
                    // If we don't have an authorization code then get one
                    $authUrl = $provider->getAuthorizationUrl($authOptions);
                    $redirectUrl = $request->getHeader('Referer')[0];
                    $clientFacade->startOAuthSession(
                        $this->getAuthProvider(),
                        $this->getOAuthProviderHash(),
                        $redirectUrl,
                        [
                            'state' => $provider->getState()
                        ]);
                    $this->getWorkbench()->stop();
                    header('Location: ' . $authUrl);
                    exit;
                }
                break;
                
                // Got an error, probably user denied access
            case !empty($requestParams['error']):
                $clientFacade->stopOAuthSession();
                // Wrap the OAuth exception in an ordinary AuthenticationFailedError to ensure they are
                // handled similarly to other types of password-mismatch errors. In particular, they
                // will produce propper 401 HTTP error codes.
                throw new AuthenticationFailedError(
                    $this,
                    'Failed to sign in with Microsoft account',
                    null,
                    new OAuthHttpException($this, 'OAuth2 error: ' . htmlspecialchars($requestParams['error'], ENT_QUOTES, 'UTF-8'), null, null, $request)
                );
                
                // If code is not empty and there is no error, process provider response here
            default:
                $sessionVars = $clientFacade->getOAuthSessionVars();
                
                if (empty($requestParams['state']) || $requestParams['state'] !== $sessionVars['state']) {
                    $clientFacade->stopOAuthSession();
                    throw new OAuthHttpException($this, 'Invalid OAuth2 state: expecting "' . $sessionVars['state'] . '", received from provider "' . $requestParams['state'] . '"!', null, null, $request);
                }
                
                // Get an access token (using the authorization code grant)
                try {
                    $oauthToken = $provider->getAccessToken('authorization_code', [
                        'code' => $requestParams['code']
                    ]);
                } catch (\Throwable $e) {
                    $clientFacade->stopOAuthSession();
                    throw new AuthenticationFailedError($this->getConnection(), $e->getMessage(), null, $e);
                }
        }
        
        $clientFacade->stopOAuthSession();
        if ($oauthToken) {
            return new OAuth2AuthenticatedToken($this->getUsername($oauthToken), $oauthToken, $token->getFacade());
        }
        
        throw new AuthenticationFailedError($this->getConnection(), 'Please sign in first!');
    }
    
    protected function getOAuthProvider() : AbstractProvider
    {
        $options = [
            'clientId'      => $this->getClientId(),
            'clientSecret'  => $this->getClientSecret(),
            'redirectUri'   => $this->getRedirectUri(),
            'accessType'    => $this->getAccessType()
        ];
        
        if (! empty($this->getScopes())) {
            $options['scopes'] = $this->getScopes();
        }
        return new Google($options);
    }
    
    protected function getUsername(AccessTokenInterface $oauthToken) : ?string
    {
        /* @var $ownerDetails \League\OAuth2\Client\Provider\GoogleUser */
        $ownerDetails = $this->getOAuthProvider()->getResourceOwner($oauthToken);
        if (($field = $this->getUsernameResourceOwnerField()) !== null) {
            return $ownerDetails->toArray()[$field];
        }
        return $ownerDetails->getEmail();
    }
    
    /**
     *
     * @param iContainOtherWidgets $container
     * @return WidgetInterface
     */
    protected function createButtonWidget(iContainOtherWidgets $container) : WidgetInterface
    {
        return WidgetFactory::createFromUxonInParent($container, new UxonObject([
            'widget_type' => 'Html',
            'hide_caption' => true,
            'inline' => true,
            'html' => <<<HTML

<div style="width: 100%; text-align: center;">   
    <div style="display: flex; justify-content: center; flex-wrap: nowrap; flex-direction: row;">           
        <a href="{$this->getOAuthClientFacade()->buildUrlForProvider($this, $this->getOAuthProviderHash())}" referrerpolicy="unsafe-url">
            <span style="float: left">
                <svg width="46px" height="46px" viewBox="0 0 46 46" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:sketch="http://www.bohemiancoding.com/sketch/ns">
                   <defs>
                        <filter x="-50%" y="-50%" width="200%" height="200%" filterUnits="objectBoundingBox" id="filter-1">
                            <feGaussianBlur stdDeviation="0.5" in="shadowOffsetOuter1" result="shadowBlurOuter1"></feGaussianBlur>
                            <feColorMatrix values="0 0 0 0 0   0 0 0 0 0   0 0 0 0 0  0 0 0 0.168 0" in="shadowBlurOuter1" type="matrix" result="shadowMatrixOuter1"></feColorMatrix>
                            <feOffset dx="0" dy="0" in="SourceAlpha" result="shadowOffsetOuter2"></feOffset>
                            <feColorMatrix values="0 0 0 0 0   0 0 0 0 0   0 0 0 0 0  0 0 0 0.084 0" in="shadowBlurOuter2" type="matrix" result="shadowMatrixOuter2"></feColorMatrix>
                            <feMerge>
                                <feMergeNode in="SourceGraphic"></feMergeNode>
                            </feMerge>
                        </filter>
                        <rect id="path-2" x="0" y="0" width="40" height="40" rx="2"></rect>
                        <rect id="path-3" x="5" y="5" width="38" height="38" rx="1"></rect>
                    </defs>
                    <g id="Google-Button" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd" sketch:type="MSPage">
                        <g id="9-PATCH" sketch:type="MSArtboardGroup" transform="translate(-608.000000, -219.000000)"></g>
                        <g id="btn_google_dark_normal" sketch:type="MSArtboardGroup" transform="translate(-1.000000, -1.000000)">
                            <g id="button" sketch:type="MSLayerGroup" transform="translate(4.000000, 4.000000)" filter="url(#filter-1)">
                                <g id="button-bg">
                                    <use fill="#4285F4" fill-rule="evenodd" sketch:type="MSShapeGroup" xlink:href="#path-2"></use>
                                    <use fill="none" xlink:href="#path-2"></use>
                                    <use fill="none" xlink:href="#path-2"></use>
                                    <use fill="none" xlink:href="#path-2"></use>
                                </g>
                            </g>
                            <g id="button-bg-copy">
                                <use fill="#FFFFFF" fill-rule="evenodd" sketch:type="MSShapeGroup" xlink:href="#path-3"></use>
                                <use fill="none" xlink:href="#path-3"></use>
                                <use fill="none" xlink:href="#path-3"></use>
                                <use fill="none" xlink:href="#path-3"></use>
                            </g>
                            <g id="logo_googleg_48dp" sketch:type="MSLayerGroup" transform="translate(15.000000, 15.000000)">
                                <path d="M17.64,9.20454545 C17.64,8.56636364 17.5827273,7.95272727 17.4763636,7.36363636 L9,7.36363636 L9,10.845 L13.8436364,10.845 C13.635,11.97 13.0009091,12.9231818 12.0477273,13.5613636 L12.0477273,15.8195455 L14.9563636,15.8195455 C16.6581818,14.2527273 17.64,11.9454545 17.64,9.20454545 L17.64,9.20454545 Z" id="Shape" fill="#4285F4" sketch:type="MSShapeGroup"></path>
                                <path d="M9,18 C11.43,18 13.4672727,17.1940909 14.9563636,15.8195455 L12.0477273,13.5613636 C11.2418182,14.1013636 10.2109091,14.4204545 9,14.4204545 C6.65590909,14.4204545 4.67181818,12.8372727 3.96409091,10.71 L0.957272727,10.71 L0.957272727,13.0418182 C2.43818182,15.9831818 5.48181818,18 9,18 L9,18 Z" id="Shape" fill="#34A853" sketch:type="MSShapeGroup"></path>
                                <path d="M3.96409091,10.71 C3.78409091,10.17 3.68181818,9.59318182 3.68181818,9 C3.68181818,8.40681818 3.78409091,7.83 3.96409091,7.29 L3.96409091,4.95818182 L0.957272727,4.95818182 C0.347727273,6.17318182 0,7.54772727 0,9 C0,10.4522727 0.347727273,11.8268182 0.957272727,13.0418182 L3.96409091,10.71 L3.96409091,10.71 Z" id="Shape" fill="#FBBC05" sketch:type="MSShapeGroup"></path>
                                <path d="M9,3.57954545 C10.3213636,3.57954545 11.5077273,4.03363636 12.4404545,4.92545455 L15.0218182,2.34409091 C13.4631818,0.891818182 11.4259091,0 9,0 C5.48181818,0 2.43818182,2.01681818 0.957272727,4.95818182 L3.96409091,7.29 C4.67181818,5.16272727 6.65590909,3.57954545 9,3.57954545 L9,3.57954545 Z" id="Shape" fill="#EA4335" sketch:type="MSShapeGroup"></path>
                                <path d="M0,0 L18,0 L18,18 L0,18 L0,0 Z" id="Shape" sketch:type="MSShapeGroup"></path>
                            </g>
                            <g id="handles_square" sketch:type="MSLayerGroup"></g>
                        </g>
                    </g>
                </svg>
            </span>
            <span style="line-height: 40px; display: inline-block; margin: 3px 3px 3px -4px; background-color: #4285F4; padding: 0 8px 0 8px; color: white; font-weight: bold; white-space: nowrap;">
                {$this->getWorkbench()->getApp('axenox.OAuth2Connector')->getTranslator()->translate('SIGN_IN_WITH')} Google
            </span>
        </a>
    </div>
</div>

HTML
        ]));
    }
    
    /**
     * 
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::setUrlAuthorize()
     */
    protected function setUrlAuthorize(string $value) : AuthenticationProviderInterface
    {
        throw new AuthenticatorConfigError($this, 'Cannot change the URLs for Google OAuth connectors!');
    }
    
    /**
     *
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getUrlAuthorize()
     */
    protected function getUrlAuthorize() : string
    {
        return $this->getOAuthProvider()->getBaseAuthorizationUrl();
    }
    
    /**
     * 
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::setUrlAccessToken()
     */
    protected function setUrlAccessToken(string $value) : AuthenticationProviderInterface
    {
        throw new AuthenticatorConfigError($this, 'Cannot change the URLs for Google OAuth connectors!');
    }
    
    /**
     *
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getUrlAccessToken()
     */
    protected function getUrlAccessToken() : string
    {
        return $this->getOAuthProvider()->getBaseAccessTokenUrl();
    }
    
    /**
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::setUrlResourceOwnerDetails()
     */
    protected function setUrlResourceOwnerDetails(string $value) : AuthenticationProviderInterface
    {
        throw new AuthenticatorConfigError($this, 'Cannot change the URLs for Google OAuth connectors!');
    }
    
    /**
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getUrlResourceOwnerDetails()
     */
    protected function getUrlResourceOwnerDetails() : string
    {
        return $this->getOAuthProvider()->getResourceOwnerDetailsUrl();
    }
    
    protected function getAccessType() : string
    {
        return $this->accessType;
    }
    
    /**
     * Access type
     * 
     * @uxon-property access_type
     * @uxon-type string
     * @uxon-default offline
     * 
     * @param string $value
     * @return AuthenticationProviderInterface
     */
    protected function setAccessType(string $value) : AuthenticationProviderInterface
    {
        $this->accessType = $value;
        return $this;
    }
}