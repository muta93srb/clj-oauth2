(ns clj-oauth2.ring
  (:require [clj-oauth2.client :as oauth2]
            [cheshire.core :as json]
            [ring.util.codec :as codec]
            [ring.util.response :as ring-response]
            [clojure.string :as string]
            [uri.core :as uri]))

(defn excluded? [request exclusion]
  (let [uri (:uri request)]
    (cond
      (coll? exclusion)
      (some = exclusion uri)
      (string? exclusion)
      (= exclusion uri)
      (fn? exclusion)
      (exclusion uri)
      (instance? java.util.regex.Pattern exclusion)
      (re-matches exclusion uri))))

;; Functions to store state, target URL, OAuth2 data in session
;; requires ring.middleware.session/wrap-session
;; state = xsrf_protection see section 10.12 of RFC6749
;; target = (string) "/"
(defn get-state-from-session [request]
  (:state (:session request)))

(defn put-state-in-session [response state]
  (assoc response :session (merge (response :session) {:state state})))

(defn get-target-from-session [request]
  (:target (:session request)))

(defn put-target-in-session [response target]
  (assoc response :session (merge (response :session) {:target target})))

(defn get-oauth2-data-from-session [request]
  (:oauth2 (:session request)))

(defn put-oauth2-data-in-session [request response oauth2-data]
  (assoc response
    :session (merge
               (or (:session response) (:session request))
               (or (find response :oauth2) {:oauth2 oauth2-data}))))

(defn clear-oauth2-data-in-session [request response]
  (assoc response
    :session (->
               (or (:session response) (:session request))
               (dissoc :oauth2))))

(def store-data-in-session
  {:get-state get-state-from-session
   :put-state put-state-in-session
   :get-target get-target-from-session
   :put-target put-target-in-session
   :get-oauth2-data get-oauth2-data-from-session
   :put-oauth2-data put-oauth2-data-in-session})

;; Parameter handling code shamelessly plundered from ring.middleware.
;; Thanks, Mark!
(defn- keyword-syntax? [s]
  (re-matches #"[A-Za-z*+!_?-][A-Za-z0-9*+!_?-]*" s))

(defn- keyify-params [target]
  (cond
    (map? target)
    (into {}
          (for [[k v] target]
            [(if (and (string? k) (keyword-syntax? k))
               (keyword k)
               k)
             (keyify-params v)]))
    (vector? target)
    (vec (map keyify-params target))
    :else
    target))

(defn- assoc-param
  "Associate a key with a value. If the key already exists in the map,
create a vector of values."
  [map key val]
  (assoc map key
             (if-let [cur (map key)]
               (if (vector? cur)
                 (conj cur val)
                 [cur val])
               val)))

(defn- parse-params
  "Parse parameters from a string into a map."
  [^String param-string encoding]
  (reduce
    (fn [param-map encoded-param]
      (if-let [[_ key val] (re-matches #"([^=]+)=(.*)" encoded-param)]
        (assoc-param param-map
                     (codec/url-decode key encoding)
                     (codec/url-decode (or val "") encoding))
        param-map))
    {}
    (string/split param-string #"&")))

(defn- submap? [map1 map2]
  "Are all the key/value pairs in map1 also in map2?"
  (every?
    (fn [item]
      (= item (find map2 (key item))))
    map1))

(defn- logout-client
  "Logging out the client means redirecting to the authorization server's logout URI"
  [logout-uri]
  {:status 302
   :headers {"Location" logout-uri}
   :body ""})

(defn- logout-callback? [request logout-callback-uri]
  "Checks if the URI is the same as the one configured as the logout callback URI"
  (= (:uri request) logout-callback-uri))

(defn oauth2-logout-callback-handler [req]
  "Ring handler that removes the oauth2 data from the session and redirects to the / route"
  (->> (ring-response/redirect "/")
       (clear-oauth2-data-in-session req)))

(defn- random-string [length]
  "Random mixed case alphanumeric"
  (let [ascii-codes (concat (range 48 58) (range 65 91) (range 97 123))]
    (apply str (repeatedly length #(char (rand-nth ascii-codes))))))

(defn redirect-to-authentication-server [request oauth2-params]
  "Returns a redirect to the authentication server"
  (let [xsrf-protection (or ((:get-state oauth2-params) request) (random-string 20))
        auth-req (oauth2/make-auth-request oauth2-params xsrf-protection)
        target (str (:uri request) (if (:query-string request) (str "?" (:query-string request))))
        response {:status 302
                  :headers {"Location" (:uri auth-req)}}]
    ((:put-target oauth2-params) ((:put-state oauth2-params) response xsrf-protection) target)))

(defn handle-authenticated-callback
  "This Ring wrapper acts as a filter, ensuring that the user has an OAuth
  token for all but a set of explicitly excluded URLs. The response from
  oauth2/get-access-token is exposed in the request via the :oauth2 key.
  Requires ring.middleware.params/wrap-params and
  ring.middleware.keyword-params/wrap-keyword-params to have been called
  first."
  [request oauth2-params]
  (let [response {:status 302
                  :headers {"Location" ((:get-target oauth2-params) request)}}
        oauth2-data (oauth2/get-access-token
                      oauth2-params
                      (:params request)
                      (oauth2/make-auth-request
                        oauth2-params
                        ((:get-state oauth2-params) request)))
        oauth2-data-with-userinfo (oauth2/add-userinfo oauth2-data oauth2-params)]
    ((:put-oauth2-data oauth2-params) request response oauth2-data-with-userinfo)))

(defn wrap-redirect-unauthenticated
  "Redirects to the authorization server when the request is not authenticated.
  Note that this wrapper only makes sense for requests that are initiated by a user, i.e not for XHR-requests.
  Requires the wrap-oauth2 to have been called first."
  [handler oauth2-params]
  (fn [request]
    (if (and (not (excluded? request (:exclude oauth2-params)))
             (nil? (:oauth2 request)))
      (redirect-to-authentication-server request oauth2-params)
      (handler request))))

(defn authenticated-callback?
  "Checks if the request uri matches the configured authenticated callback uri"
  [request oauth2-params]
  (= (:uri request) (.getPath (uri/make (:redirect-uri oauth2-params)))))

(defn wrap-authenticated-callback
  "Handles authentication callbacks from the authorization server"
  [handler oauth2-params]
  (fn [request]
    (if (authenticated-callback? request oauth2-params)
      (handle-authenticated-callback request oauth2-params)
      (handler request))))

(defn wrap-logout
  "Logs the client out of the authorization server session if the request is to the local logout URI"
  [handler {:keys [logout-uri-client logout-uri]}]
  (fn [request]
    (if (= (:uri request) logout-uri-client)
      (logout-client logout-uri)
      (handler request))))

(defn wrap-logout-callback
  "Handles logout callbacks from the authorization server to log the user out of the local session as well"
  [handler {:keys [logout-callback-fn logout-callback-uri]}]
  (fn [request]
    (if (logout-callback? request logout-callback-uri)
      (logout-callback-fn request)
      (handler request))))

(defn update-oauth2-data [request oauth2-data]
  (update request :oauth2 (fn [old]
                            (-> old
                                (assoc :access-token (:access_token oauth2-data))
                                (assoc :refresh-token (:refresh_token oauth2-data))
                                (assoc :params (dissoc oauth2-data :access_token :token_type))))))

(defn accept-html? [request]
  (let [accept-header (get-in request [:headers "accept"] "")]
    (re-find (re-pattern "text/html") accept-header)))

(defn refresh-token-error []
  {:status 400
   :headers {"Content-Type" "application/json; charset=utf-8"}
   :body (json/generate-string {:error "Refresh token failed"
                                :errorcode "refresh-token-failed"})})

(defn failed-refresh-response
  "Returned when refreshing the tokens fails. Dependning on the accept header, either redirect the user to
  login again with the authentication server or return a 400 error"
  [request oauth2-params]
  (if (accept-html? request)
    (redirect-to-authentication-server request oauth2-params)
    (refresh-token-error)))

(defn- refresh-oauth-data
  "Attempts to refresh an access token using a refresh token.
  If the refresh fails an error is returned indicating the refresh failed"
  [handler request oauth2-params]
  (let [[success? oauth2-update] (oauth2/refresh-access-token (:refresh-token (:oauth2 request)) oauth2-params)]
    (if success?
      (let [refreshed (update-oauth2-data request oauth2-update)
            response (handler refreshed)]
        (assoc response :oauth2 (:oauth2 refreshed)))
      (failed-refresh-response request oauth2-params))))

(defn wrap-validate-oauth-data
  "Validates the request according to the Oauth contract

  Note:
  - requests to excluded URIs are skipped
  - only requests with oauth2-data are validated

  Validation implies the following:
  - Checking the validity of the access token against the authorization server API
  - Attempting to refresh the access token in the case it has expired"
  [handler oauth2-params]
  (fn [request]
    (cond (excluded? request (:exclude oauth2-params))
          (handler request)

          (not (:oauth2 request))
          (handler request)

          (oauth2/valid-auth-token? (:token-info-uri oauth2-params) (:access-token (:oauth2 request)))
          (handler request)

          :else
          (refresh-oauth-data handler request oauth2-params))))

(defn wrap-add-oauth-data
  "Adds :oauth2 key to the request"
  [handler oauth2-params]
  (fn [request]
    (if (excluded? request (:exclude oauth2-params))
      (handler request)
      (let [oauth2-data ((:get-oauth2-data oauth2-params) request)]
        (if (nil? oauth2-data)
          (handler request)
          ;; Add oauth2 data to request and response
          (if-let [response (handler (assoc request :oauth2 oauth2-data))]
            ((:put-oauth2-data oauth2-params) request response oauth2-data)))))))

(defn wrap-oauth2
  [handler oauth2-params]
  "Handles oauth2 requests for
    - authorization redirects from the authorization server
    - client logout
    - logout redirects from the authorization server
    - validating access tokens against the authorization server on every request
    - refreshing access tokens that expire

    Requests are delegated to the handler directly if the uri is excluded/blacklisted or when
    the :get-oauth2-data function does not return oauth data.

    If there is oauth data, then it is added to the request/response with the :oauth2 key"
  (-> handler
      (wrap-validate-oauth-data oauth2-params)
      (wrap-add-oauth-data oauth2-params)
      (wrap-authenticated-callback oauth2-params)
      (wrap-logout-callback oauth2-params)
      (wrap-logout oauth2-params)))