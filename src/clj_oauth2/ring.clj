(ns clj-oauth2.ring
  (:require [clj-oauth2.client :as oauth2]
            [ring.util.codec :as codec]
            [ring.util.response :as ring-response]
            [clojure.string :as string]
            [uri.core :as uri]))

(defn excluded? [uri oauth2-params]
  (let [exclusion (:exclude oauth2-params)]
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

(defn request-uri [request oauth2-params]
  (let [scheme (if (:force-https oauth2-params) "https" (name (:scheme request)))
        port (if (or (and (= (name (:scheme request)) "http")
                          (not= (:server-port request) 80))
                     (and (= (name (:scheme request)) "https")
                          (not= (:server-port request) 443)))
               (str ":" (:server-port request)))]
    (str scheme "://" (:server-name request) port (:uri request))))

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

(defn is-callback [request oauth2-params]
  "Returns true if this is a request to the callback URL"
  (let [oauth2-url-vector (string/split (.toString (java.net.URI. (:redirect-uri oauth2-params))) #"\?")
        oauth2-uri (nth oauth2-url-vector 0)
        oauth2-url-params (nth oauth2-url-vector 1 "")
        encoding (or (:character-encoding request) "UTF-8")]
    (and (= oauth2-uri (request-uri request oauth2-params))
         (submap? (keyify-params (parse-params oauth2-url-params encoding)) (:params request)))))

(defn- logout? [uri oauth2-params]
  "Checks if the uri is the same as the one configured as the client logout URI"
  (= (:logout-uri-client oauth2-params) (.getPath (uri/make uri))))

(defn- logout-client [request oauth2-params]
  "Logging out the client means redirecting to the authorization server's logout URI"
  {:status 302
   :headers {"Location" (:logout-uri oauth2-params)}
   :body ""})

(defn- logout-callback? [uri oauth2-params]
  "Checks if the URI is the same as the one configured as the logout callback URI"
  (= (:logout-callback-uri oauth2-params) (.getPath (uri/make uri))))

(defn oauth2-logout-callback-handler [req]
  "Ring handler that removes the oauth2 data from the session and redirects to the / route"
  (->> (ring-response/redirect "/")
       (clear-oauth2-data-in-session req)))

(defn- random-string [length]
  "Random mixed case alphanumeric"
  (let [ascii-codes (concat (range 48 58) (range 65 91) (range 97 123))]
    (apply str (repeatedly length #(char (rand-nth ascii-codes))))))

(defn redirect-to-authentication-server [_ request oauth2-params]
  "Returns a redirect to the authentication server"
  (let [xsrf-protection (or ((:get-state oauth2-params) request) (random-string 20))
        auth-req (oauth2/make-auth-request oauth2-params xsrf-protection)
        target (str (:uri request) (if (:query-string request) (str "?" (:query-string request))))
        response {:status 302
                  :headers {"Location" (:uri auth-req)}}]
    ((:put-target oauth2-params) ((:put-state oauth2-params) response xsrf-protection) target)))

;; This Ring wrapper acts as a filter, ensuring that the user has an OAuth
;; token for all but a set of explicitly excluded URLs. The response from
;; oauth2/get-access-token is exposed in the request via the :oauth2 key.
;; Requires ring.middleware.params/wrap-params and
;; ring.middleware.keyword-params/wrap-keyword-params to have been called
;; first.
(defn handle-auth-callback [request oauth2-params]
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

(defn wrap-redirect-unauthenticated [handler oauth2-params]
  "Redirects to the authorization server when the request is not authenticated.
  Note that this wrapper only makes sense for requests that are initiated by a user, i.e not for XHR-requests.
  Requires the wrap-oauth2 to have been called first."
  (fn [request]
    (if (and (not (excluded? (:uri request) oauth2-params))
             (nil? (:oauth2 request)))
      (redirect-to-authentication-server handler request oauth2-params)
      (handler request))))

(defn wrap-oauth2
  [handler oauth2-params]
  "Handles oauth2 requests for
    - authorization redirects from the authorization server
    - client logout
    - logout redirects from the authorization server

    Requests are delegated to the handler directly if the uri is excluded/blacklisted or when
    the :get-oauth2-data function does not return oauth data.

    If the :get-oauth2-data function returns oauth data, then it is added to the request with the :oauth2 key."

  (fn [request]
    (cond (excluded? (:uri request) oauth2-params)
          (handler request)

          ;; Redirect the client to the authorization server
          (logout? (:uri request) oauth2-params)
          (logout-client request oauth2-params)

          ;; The authorization server redirects the client back to this URL after successful logout
          (logout-callback? (:uri request) oauth2-params)
          ((:logout-callback-fn oauth2-params) request)

          ;; We should have an authorization code - get the access token, put
          ;; it in the response and redirect to the originally requested URL
          (is-callback request oauth2-params)
          (handle-auth-callback request oauth2-params)

          :else
          (let [oauth2-data ((:get-oauth2-data oauth2-params) request)]
            (if (nil? oauth2-data)
              (handler request)
              ;; We have oauth2 data - Add oauth2 to the request-map
              (if-let [response (handler (assoc request :oauth2 oauth2-data))]
                ((:put-oauth2-data oauth2-params) request response oauth2-data)))))))