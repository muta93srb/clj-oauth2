(ns clj_oauth2.ring-test
  (:require [clojure.test :refer :all]
            [clj-oauth2.ring :as r]
            [clojure.pprint :refer [pprint]]
            [clj-oauth2.stub :as stub]))

;; Start an authentication server stub to run the tests against
(use-fixtures :once stub/server)

;; Stubbed out response that makes it possible verify that a handler was invoked by the wrapper
(def ok-response {:status 200
                  :body "ok"
                  :headers {}})

(def unused-response {:status 500
                      :body "should not be invoked"
                      :headers {}})

(deftest can-exclude-handlers
  (let [wrapper-fn (r/wrap-oauth2 (fn [req] ok-response) {:exclude "excluded"
                                                          :redirect-uri "notused"})]
    (is (= (wrapper-fn {:uri "excluded"
                        :scheme "http"}) ok-response))))

(deftest existing-oauth-data-are-returned-in-response
  (let [oauth2-config {:get-oauth2-data r/get-oauth2-data-from-session
                       :put-oauth2-data r/put-oauth2-data-in-session
                       :redirect-uri "not-used"
                       :token-info-uri (str stub/server-uri "/tokeninfo")}
        wrapper-fn (r/wrap-oauth2 (fn [req] ok-response)
                                  oauth2-config)]
    (is (= (wrapper-fn {:scheme "https"
                        :uri "whatever"
                        :session {:oauth2 {:access-token stub/access-token-valid}}})
           (merge ok-response {:session {:oauth2 {:access-token stub/access-token-valid}}})))))

(deftest invalid-authentication-tokens-are-refreshed
  (let [oauth2-config {:get-oauth2-data r/get-oauth2-data-from-session
                       :put-oauth2-data r/put-oauth2-data-in-session
                       :redirect-uri "not-used"
                       :token-info-uri (str stub/server-uri "/tokeninfo")
                       :access-token-uri (str stub/server-uri "/token-refresh")}
        wrapper-fn (r/wrap-oauth2 (fn [req] ok-response)
                                  oauth2-config)
        response (wrapper-fn {:scheme "https"
                              :uri "whatever"
                              :session {:oauth2 {:access-token stub/access-token-invalid}}})]
    (is (= (:status response) 200))
    (is (= (:body response) "ok"))
    (is (= (get-in response [:session :oauth2])
           {:access-token "sesame"
            :refresh-token "new-foo"
            :params {:expires_in 120
                     :refresh_token "new-foo"}}))))

(deftest failure-to-refresh-tokens-fails-the-request
  (testing "redirect html requests"
    (let [oauth2-config {:get-oauth2-data r/get-oauth2-data-from-session
                         :put-oauth2-data r/put-oauth2-data-in-session
                         :get-state r/get-state-from-session
                         :put-state r/put-state-in-session
                         :get-target r/get-target-from-session
                         :put-target r/put-target-in-session
                         :redirect-uri "somewhere"
                         :token-info-uri (str stub/server-uri "/tokeninfo")
                         :access-token-uri (str stub/server-uri "/token-refresh-always-fails")}
          wrapper-fn (r/wrap-oauth2 (fn [req] ok-response)
                                    oauth2-config)
          response (wrapper-fn {:scheme "https"
                                :uri "whatever"
                                :headers {"accept" "text/html"}
                                :session {:oauth2 {:access-token stub/access-token-invalid}}})]
      (is (= (:status response) 302))
      (is (get-in response [:headers "Location"]))))

  (testing "redirect non-html requests"
    (let [oauth2-config {:get-oauth2-data r/get-oauth2-data-from-session
                         :put-oauth2-data r/put-oauth2-data-in-session
                         :redirect-uri "not-used"
                         :token-info-uri (str stub/server-uri "/tokeninfo")
                         :access-token-uri (str stub/server-uri "/token-refresh-always-fails")}
          wrapper-fn (r/wrap-oauth2 (fn [req] ok-response)
                                    oauth2-config)
          response (wrapper-fn {:scheme "https"
                                :uri "whatever"
                                :headers {:accept "application/json"}
                                :session {:oauth2 {:access-token stub/access-token-invalid}}})]
      (is (= (:status response) 400))
      (is (= (:headers response) {"Content-Type" "application/json; charset=utf-8"}))
      (is (= (:body response) "{\"error\":\"Refresh token failed\",\"errorcode\":\"refresh-token-failed\"}")))))

(deftest missing-oauth-data-results-in-fall-through
  (let [oauth2-config {:get-oauth2-data r/get-oauth2-data-from-session
                       :put-oauth2-data r/put-oauth2-data-in-session
                       :get-state r/get-state-from-session
                       :put-state r/put-state-in-session
                       :get-target r/get-target-from-session
                       :put-target r/put-target-in-session
                       :redirect-uri "somewhere"}
        wrapper-fn (r/wrap-oauth2 (fn [_] ok-response)
                                  oauth2-config)
        response (wrapper-fn {:scheme "https"
                              :uri "whatever"
                              :session {}})]
    (is (= (:status response) 200))))

(deftest handle-client-logout
  (testing "handle the client logout uri by redirecting to authorization server"
    (let [oauth2-config {:get-oauth2-data r/get-oauth2-data-from-session
                         :put-oauth2-data r/put-oauth2-data-in-session
                         :get-state r/get-state-from-session
                         :put-state r/put-state-in-session
                         :get-target r/get-target-from-session
                         :put-target r/put-target-in-session
                         :redirect-uri "not-used"
                         :logout-uri "https://auth-server.com/logout"
                         :logout-uri-client "logout"
                         :logout-callback-uri "not-used-in-test"}
          wrapper-fn (r/wrap-oauth2 (fn [req] unused-response)
                                    oauth2-config)
          response (wrapper-fn {:scheme "https"
                                :uri "logout"
                                :session {:oauth2 {:sample-data "data!"}}})]
      (is (= (:status response) 302))
      (is (= (get-in response [:headers "Location"])
             (:logout-uri oauth2-config)))))

  (testing "execute the logout callback when handling the logout callback uri"
    (let [oauth2-config {:get-oauth2-data r/get-oauth2-data-from-session
                         :put-oauth2-data r/put-oauth2-data-in-session
                         :get-state r/get-state-from-session
                         :put-state r/put-state-in-session
                         :get-target r/get-target-from-session
                         :put-target r/put-target-in-session
                         :redirect-uri "not-used"
                         :logout-uri "https://auth-server.com/logout"
                         :logout-uri-client "logout"
                         :logout-callback-uri "oauthpostlogout"
                         :logout-callback-fn r/oauth2-logout-callback-handler}
          wrapper-fn (r/wrap-oauth2 (fn [req] unused-response)
                                    oauth2-config)
          response (wrapper-fn {:scheme "https"
                                :uri "oauthpostlogout"
                                :session {:something "keep it"
                                          :oauth2 {:sample-data "data!"}}})]

      (is (= (:status response) 302))
      (is (= (:session response) {:something "keep it"})))))

(deftest test-wrapper-for-redirect-on-unauthenticated
  (testing "missing oauth data results in redirect to authorization server"
    (let [oauth2-config {:get-oauth2-data r/get-oauth2-data-from-session
                         :put-oauth2-data r/put-oauth2-data-in-session
                         :get-state r/get-state-from-session
                         :put-state r/put-state-in-session
                         :get-target r/get-target-from-session
                         :put-target r/put-target-in-session
                         :redirect-uri "somewhere"}
          wrapper-fn (r/wrap-redirect-unauthenticated (fn [_] unused-response)
                                                      oauth2-config)
          response (wrapper-fn {:scheme "https"
                                :uri "whatever"
                                :session {}})]
      (is (= (:status response) 302))
      (is (get-in response [:headers "Location"]))))

  (testing "oauth data results in fall through"
    (let [oauth2-config {:get-oauth2-data r/get-oauth2-data-from-session
                         :put-oauth2-data r/put-oauth2-data-in-session
                         :get-state r/get-state-from-session
                         :put-state r/put-state-in-session
                         :get-target r/get-target-from-session
                         :put-target r/put-target-in-session
                         :redirect-uri "somewhere"}
          wrapper-fn (r/wrap-redirect-unauthenticated (fn [_] ok-response)
                                                      oauth2-config)
          response (wrapper-fn {:scheme "https"
                                :uri "whatever"
                                :oauth2 {:data "data"}})]
      (is (= (:status response) 200))))

  (testing "excluded url results in fall through"
    (let [oauth2-config {:get-oauth2-data r/get-oauth2-data-from-session
                         :put-oauth2-data r/put-oauth2-data-in-session
                         :get-state r/get-state-from-session
                         :put-state r/put-state-in-session
                         :get-target r/get-target-from-session
                         :put-target r/put-target-in-session
                         :redirect-uri "somewhere"
                         :exclude #"^\/(?=ping|public).*"}
          wrapper-fn (r/wrap-redirect-unauthenticated (fn [_] ok-response)
                                                      oauth2-config)
          response (wrapper-fn {:scheme "https"
                                :uri "/ping"
                                :session {}})]
      (is (= (:status response) 200)))))