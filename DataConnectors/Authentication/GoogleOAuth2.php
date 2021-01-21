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
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use Psr\Http\Message\RequestInterface;
use axenox\GoogleConnector\CommonLogic\Security\Authenticators\GoogleOAuth2Trait;
use exface\Core\Interfaces\Security\AuthenticationProviderInterface;
use exface\UrlDataConnector\Interfaces\HttpConnectionInterface;

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
        
        return $this->exchangeOAuthToken($token);
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
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface::getConnection()
     */
    public function getConnection() : HttpConnectionInterface
    {
        return $this->connection;
    }
}