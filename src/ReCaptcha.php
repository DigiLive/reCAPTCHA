<?php

declare(strict_types=1);

namespace DigiLive\reCAPTCHA;

/**
 * Class reCAPTCHA
 *
 * @see     https://developers.google.com/reCAPTCHA/docs/v3
 * @see     https://www.phptreepoint.com/google-reCAPTCHA-v3-in-php/
 * @package DigiLive\reCAPTCHA
 */
class reCAPTCHA
{
    /**
     * Url to Googles reCAPTCHA v3 API.
     */
    public const API_URL = 'https://www.google.com/reCAPTCHA/api/siteverify';
    /**
     * @var string JSON encoded string response from the API.
     */
    private string $apiResponse;
    /**
     * @var string Secret reCAPTCHA key.
     * @see https://www.google.com/reCAPTCHA/admin
     */
    private string $reCAPTCHASecretKey;
    /**
     * @var string Action value at the time of token generation.
     */
    private string $reCAPTCHAAction;
    /**
     * @var float Threshold value for defining human or bot request.
     */
    private float $threshold;

    /**
     * reCAPTCHA constructor.
     *
     * @param   string  $reCAPTCHASecretKey  Secret reCAPTCHA key.
     */
    public function __construct(string $reCAPTCHASecretKey)
    {
        $this->reCAPTCHASecretKey = $reCAPTCHASecretKey;
    }

    /**
     * Get a html script tag for including googles reCAPTCHA V3 javascript to html.
     *
     * The script tag is either sent to the outputbuffer with appropriate response headers or return as a string.
     * Define to defer loading of the script by setting the last parameter.
     *
     * @param   string  $siteKey  Public reCAPTCHA key.
     * @param   bool    $render   Set to true to render the tag.
     * @param   bool    $defer    Set to True to include the defer attribute to the tag.
     *
     * @return string Script tag.
     */
    public static function getScriptTag(string $siteKey, bool $render = true, bool $defer = true): string
    {
        $defer       = $defer ? 'defer' : '';
        $returnValue = <<<HTML
    <script src="https://www.google.com/reCAPTCHA/api.js?render=$siteKey" $defer></script>
HTML;
        if ($render) {
            header_remove();
            header("Cache-Control: no-transform,public,max-age=300,s-maxage=900");
            header('Content-Type: text/html; charset=UTF-8');
            echo $returnValue;
            exit;
        }

        return $returnValue;
    }

    /**
     * Define an "action" value to verify the request with.
     *
     * This should be the same value of the action parameter which was used at the time of token generation.
     *
     * @param   string  $action  Value of action at token generation.
     */
    public function setAction(string $action)
    {
        $this->reCAPTCHAAction = $action;
    }

    /**
     * Set the threshold of the reCAPTCHA score for defining the request as human or bot.
     *
     * If the score is equal or greater than this value, the request is identified as a human request.
     * Any lower score will define the request as a bot request.
     *
     * @param   float  $threshold  Limit value to identify hte request as human or bot.
     */
    public function setThresholdScore(float $threshold)
    {
        $this->threshold = $threshold;
    }

    /**
     * Validate the response of the reCAPTCHA api.
     *
     * This method returns true when the request is considered to be human.
     *
     * @return bool True of Human request, false otherwise.
     */
    public function validateResponse(): bool
    {
        $responseArray = json_decode($this->apiResponse, true);

        return
            $responseArray['success'] &&
            $responseArray['action'] == $this->reCAPTCHAAction &&
            $responseArray['score'] >= $this->threshold &&
            $responseArray == $_SERVER['SERVER_NAME'];
    }

    /**
     * Get a validation response from the reCAPTCHA api.
     *
     * E.g.
     * {
     * "success": true|false,      // Whether this request was a valid reCAPTCHA token for your site
     * "score": number             // The score for this request (0.0 - 1.0)
     * "action": string            // The action name for this request (important to verify)
     * "challenge_ts": timestamp,  // Timestamp of the challenge load (ISO format yyyy-MM-dd'T'HH:mm:ssZZ)
     * "hostname": string,         // The hostname of the site where the reCAPTCHA was solved
     * "error-codes": [...]        // Optional, when an error occurred.
     * }
     *
     * @return string
     */
    public function getApiResponse(): string
    {
        $curlOptions = [
            CURLOPT_URL            => self::API_URL,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query(
                ['secret' => $this->reCAPTCHASecretKey, 'response' => $_POST['token']]
            ),
            CURLOPT_RETURNTRANSFER => true,
        ];

        $curlHandle = curl_init();
        curl_setopt_array($curlHandle, $curlOptions);
        $response = curl_exec($curlHandle);
        curl_close($curlHandle);
        $this->apiResponse = $response;

        return $response;
    }

    /**
     * Send the reCAPTCHA api response to the output buffer with appropriate response headers.
     */
    public function sendApiResponse()
    {
        header_remove();
        header("Cache-Control: no-transform,public,max-age=300,s-maxage=900");
        header('Content-Type: application/json');
        echo $this->apiResponse;
        exit;
    }
}
