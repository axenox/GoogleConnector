<?php
namespace axenox\GoogleConnector\DataConnectors\Authentication;

use exface\Core\CommonLogic\UxonObject;
use exface\UrlDataConnector\Interfaces\UrlConnectionInterface;
use exface\Core\CommonLogic\Traits\ImportUxonObjectTrait;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2AccessToken;
use exface\Core\Exceptions\InvalidArgumentException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use exface\Core\Exceptions\Security\AuthenticationFailedError;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use axenox\OAuth2Connector\Exceptions\OAuthInvalidStateException;
use Psr\Http\Message\RequestInterface;
use axenox\GoogleConnector\CommonLogic\Security\Authenticators\GoogleOAuth2Trait;

class GoogleOAuth2 implements HttpAuthenticationProviderInterface
{
    use ImportUxonObjectTrait;
    use GoogleOAuth2Trait;
    
    private $connection = null;
    
    private $originalUxon = null;
    
    private $storedToken = null;
    
    private $refreshToken = null;
    
    /**
     *
     * @param UrlConnectionInterface $dataConnection
     * @param UxonObject $uxon
     */
    public function __construct(UrlConnectionInterface $dataConnection, UxonObject $uxon = null)
    {
        $this->connection = $dataConnection;
        if ($uxon !== null) {
            $this->originalUxon = $uxon;
            $this->importUxonObject($uxon, ['class']);
        }
    }
    
    public function authenticate(AuthenticationTokenInterface $token): AuthenticationTokenInterface
    {
        if (! $token instanceof OAuth2RequestToken) {
            throw new InvalidArgumentException('Cannot use token ' . get_class($token) . ' in OAuth2 authentication: only OAuth2RequestToken or derivatives allowed!');
        }
        
        $facade = $token->getFacade();
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
                        if (! $this->getRefreshToken()) {
                            $authOptions = ['prompt' => 'consent'];
                        } else {
                            $oauthToken = $provider->getAccessToken('refresh_token', [
                                'refresh_token' => $this->getRefreshToken()
                            ]);
                        }
                    } 
                }
                if (! $oauthToken || ! empty($authOptions)) {
                    // If we don't have an authorization code then get one
                    $authUrl = $provider->getAuthorizationUrl($authOptions);
                    $redirectUrl = $request->getHeader('Referer')[0];
                    $this->getOAuthClientFacade()->startOAuthSession(
                        $this->getConnection(),
                        $redirectUrl,
                        [
                            'state' => $provider->getState()
                        ]);
                    header('Location: ' . $authUrl);
                    exit;
                }
                break;
            
            // Got an error, probably user denied access
            case !empty($requestParams['error']):
                $facade->stopOAuthSession();
                throw new AuthenticationFailedError($this, 'OAuth2 error: ' . htmlspecialchars($requestParams['error'], ENT_QUOTES, 'UTF-8'));
                
            // If code is not empty and there is no error, process provider response here
            default:
                $sessionVars = $facade->getOAuthSessionVars();
                
                if (empty($requestParams['state']) || $requestParams['state'] !== $sessionVars['state']) {
                    $facade->stopOAuthSession();
                    throw new OAuthInvalidStateException($this, 'Invalid OAuth2 state!');
                }
            
                // Get an access token (using the authorization code grant)
                try {
                    $oauthToken = $provider->getAccessToken('authorization_code', [
                        'code' => $requestParams['code']
                    ]);
                } catch (\Throwable $e) {
                    $facade->stopOAuthSession();
                    throw new AuthenticationFailedError($this->getConnection(), $e->getMessage(), null, $e);
                }
        }
        
        $facade->stopOAuthSession();
        if ($oauthToken) {
            return new OAuth2AccessToken($this->getUsername($oauthToken, $provider), $oauthToken, $token->getFacade());
        }
        
        throw new AuthenticationFailedError($this->getConnection(), 'Please sign in first!');
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface::getDefaultRequestOptions()
     */
    public function getDefaultRequestOptions(array $defaultOptions): array
    {
        return $defaultOptions;
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface::signRequest()
     */
    public function signRequest(RequestInterface $request) : RequestInterface
    {
        $token = $this->getTokenStored();
        if ($token) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $token->getToken());
        }
        return $request;
    }
    
    /**
     * 
     * @return UrlConnectionInterface
     */
    protected function getConnection() : UrlConnectionInterface
    {
        return $this->connection;
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\WorkbenchDependantInterface::getWorkbench()
     */
    public function getWorkbench()
    {
        return $this->connection->getWorkbench();
    }

    /**
     * 
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface::getCredentialsUxon()
     */
    public function getCredentialsUxon(AuthenticationTokenInterface $authenticatedToken): UxonObject
    {
        if (! $authenticatedToken instanceof OAuth2AccessToken) {
            throw new InvalidArgumentException('Cannot store authentication token ' . get_class($authenticatedToken) . ' in OAuth2 credentials: only OAuth2AccessToken or derivatives supported!');
        }
        
        $accessToken = $authenticatedToken->getAccessToken();
        $uxon = new UxonObject([
            'authentication' => [
                'class' => '\\' . get_class($this),
                'token' => $accessToken->jsonSerialize(),
                'refresh_token' => $accessToken->getRefreshToken() ? $accessToken->getRefreshToken() : $this->getRefreshToken()
            ]
        ]);
        
        return $uxon;
    }
    
    protected function setToken(UxonObject $uxon) : GoogleOAuth2
    {
        $this->storedToken = new AccessToken($uxon->toArray());
        return $this;
    }
    
    protected function getTokenStored() : ?AccessTokenInterface
    {
        return $this->storedToken;
    }
    
    public function exportUxonObject()
    {
        return $this->originalUxon ?? new UxonObject();
    }
    
    protected function getRefreshToken() : ?string
    {
        return $this->refreshToken;
    }
    
    /**
     * 
     * @param string|null $value
     * @return GoogleOAuth2
     */
    protected function setRefreshToken($value) : GoogleOAuth2
    {
        $this->refreshToken = $value;
        return $this;
    }
    
    protected function getAuthProvider() : AuthenticationProviderInterface
    {
        return $this->getConnection();
    }
    
    protected function getOAuthClientFacadeRequestUri() : string
    {
        return $this->getRedirectUri() . '/' .$this->getConnection()->getAliasWithNamespace();
    }
}