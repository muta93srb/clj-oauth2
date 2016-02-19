(ns clj-oauth2.stub
  (:require [uri.core :as uri]
            [cheshire.core :as json]
            [clojure.string :as str]
            [ring.adapter.jetty :as ring])
  (:import [org.apache.commons.codec.binary Base64]))

(def port 18080)
(def host "localhost")
(def server-uri (str "http://" host ":" port))

(def access-token-valid "always valid")
(def access-token-invalid "always invalid")

(def access-token
  {:access-token "sesame"
   :query-param :access_token
   :token-type "bearer"
   :expires-in 120
   :refresh-token "new-foo"})

(def endpoint
  {:client-id "foo"
   :client-secret "bar"
   :access-query-param :access_token
   :scope ["foo" "bar"]})

(def endpoint-auth-code
  (assoc endpoint
    :redirect-uri "http://my.host/cb"
    :grant-type "authorization_code"
    :authorization-uri "http://localhost:18080/auth"
    :access-token-uri "http://localhost:18080/token-auth-code"))

(def endpoint-resource-owner
  (assoc endpoint
    :grant-type "password"
    :access-token-uri "http://localhost:18080/token-password"))

(def resource-owner-credentials
  {:username "foo"
   :password "bar"})

(defn parse-auth-header [req]
  (let [header (get-in req [:headers "authorization"] "")
        [scheme param] (rest (re-matches #"\s*(\w+)\s+(.+)" header))]
    (when-let [scheme (and scheme param (.toLowerCase scheme))]
      [scheme param])))

(defn parse-base64-auth-header [req]
  (let [header (get-in req [:headers "authorization"] "")
        [scheme param] (rest (re-matches #"\s*(\w+)\s+(.+)" header))]
    (when-let [scheme (and scheme param (.toLowerCase scheme))]
      [scheme (String. (Base64/decodeBase64 param) "UTF-8")])))

(defn parse-basic-auth-header [req]
  (let [[scheme param] (parse-base64-auth-header req)]
    (and scheme param
         (= "basic" scheme)
         (str/split param #":" 2))))


(defn- handle-protected-resource [req grant & [deny]]
  (let [query (uri/form-url-decode (:query-string req))
        [scheme param] (parse-auth-header req)
        bearer-token (and (= scheme "bearer") param)
        token (or bearer-token (:access_token query))]
    (if (= token (:access-token access-token))
      {:status 200 :body (if (fn? grant) (grant token) grant)}
      {:status 400 :body (or deny "nope")})))

(defn- client-authenticated? [req endpoint]
  (let [body (:body req)
        [client-id client-secret]
        (or (parse-basic-auth-header req)
            [(:client_id body) (:client_secret body)])]
    (and (= client-id (:client-id endpoint))
         (= client-secret (:client-secret endpoint)))))

(defn- token-response [req access-token]
  {:status 200
   :headers {"content-type" (str "application/"
                                 (if (contains? (:query-params req) :formurlenc)
                                   "x-www-form-urlencoded"
                                   "json")
                                 "; charset=UTF-8")}
   :body ((if (contains? (:query-params req) :formurlenc)
            uri/form-url-encode
            json/generate-string)
           (let [{:keys [access-token
                         token-type
                         expires-in
                         refresh-token]}
                 access-token]
             {:access_token access-token
              :token_type token-type
              :expires_in expires-in
              :refresh_token refresh-token}))})

;; shamelessly copied from clj-http tests
(defn handler [req]

  (let [req (assoc req :query-params (some-> req :query-string uri/form-url-decode))]
    (condp = [(:request-method req) (:uri req)]
      [:post "/token-auth-code"]
      (let [{body :body :as req} (update req :body (comp uri/form-url-decode slurp))]
        (if (and (= (:code body) "abracadabra")
                 (= (:grant_type body) "authorization_code")
                 (client-authenticated? req endpoint-auth-code)
                 (= (:redirect_uri body) (:redirect-uri endpoint-auth-code)))
          (token-response req access-token)
          {:status 400 :body "error=fail&error_description=invalid"}))
      [:post "/token-password"]
      (let [body (uri/form-url-decode (slurp (:body req)))
            req (assoc req :body body)]
        (if (and (= (:grant_type body) "password")
                 (= (:username body) (:username resource-owner-credentials))
                 (= (:password body) (:password resource-owner-credentials))
                 (client-authenticated? req endpoint-resource-owner))
          (token-response req access-token)
          {:status 400 :body "error=fail&error_description=invalid"}))
      [:post "/token-refresh"]
      (token-response req access-token)
      [:post "/token-refresh-always-fails"]
      {:status 400 :body (json/generate-string {:error "fail"
                                                :error_description "Refresh token expired"})}
      [:get "/tokeninfo"]
      (if (= (get-in req [:query-params :access_token]) access-token-valid)
        {:status 200
         :body (json/generate-string {:client-id (:client-id endpoint)
                                      :scope ["foo" "bar"]
                                      :userid "foo"
                                      :ttl "3447"})}
        {:status 400
         :body (json/generate-string {:error "invalid_token"
                                      :error_description "Token does not exist, or it has expired"})})
      [:post "/token-error"]
      {:status 400
       :headers {"content-type" "application/json"}
       :body (json/generate-string {:error "unauthorized_client"
                                    :error_description "not good"})}
      [:get "/some-resource"]
      (handle-protected-resource req "that's gold jerry!")
      [:get "/query-echo"]
      (handle-protected-resource req (:query-string req))
      [:get "/query-and-token-echo"]
      (handle-protected-resource req
                                 (fn [token]
                                   (uri/form-url-encode
                                     (assoc (:query-params req)
                                       :access_token token))))
      [:get "/get"]
      (handle-protected-resource req "get")
      [:post "/post"]
      (handle-protected-resource req "post")
      [:put "/put"]
      (handle-protected-resource req "put")
      [:delete "/delete"]
      (handle-protected-resource req "delete")
      [:head "/head"]
      (handle-protected-resource req "head"))))

(defn server
  [tests]
  (let [server (ring/run-jetty handler {:port 18080 :join? false})]
    (tests)
    (.stop server)))