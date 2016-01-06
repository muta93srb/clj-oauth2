(ns clj_oauth2.ring-test
  (:require [clojure.test :refer :all]
            [clj-oauth2.ring :as r]))

;; Stubbed out response that makes it possible verify that a handler was invoked by the wrapper
(def ok-response {:status 200
                  :body "ok"
                  :headers {}})

(def unused-response {:status 500
                      :body "should not be invoked"
                      :headers {}})

(deftest can-exclude-handlers
  (let [wrapper-fn (r/wrap-oauth2 (fn [req] ok-response) {:exclude "excluded"})]
    (is (= (wrapper-fn {:uri "excluded"}) ok-response))))

(deftest existing-oauth-data-are-returned-in-response
  (let [oauth2-config {:get-oauth2-data r/get-oauth2-data-from-session
                       :put-oauth2-data r/put-oauth2-data-in-session
                       :redirect-uri "not-used"}
        wrapper-fn (r/wrap-oauth2 (fn [req] ok-response)
                                  oauth2-config)]
    (is (= (wrapper-fn {:scheme "https"
                        :uri "whatever"
                        :session {:oauth2 {:sample-data "data!"}}})
           (merge ok-response {:session {:oauth2 {:sample-data "data!"}}})))))

(deftest missing-oauth-data-results-in-redirect-to-oauth-provider
  (let [oauth2-config {:get-oauth2-data r/get-oauth2-data-from-session
                       :put-oauth2-data r/put-oauth2-data-in-session
                       :get-state r/get-state-from-session
                       :put-state r/put-state-in-session
                       :get-target r/get-target-from-session
                       :put-target r/put-target-in-session
                       :redirect-uri "somewhere"}
        wrapper-fn (r/wrap-oauth2 (fn [_] unused-response)
                                  oauth2-config)
        response (wrapper-fn {:scheme "https"
                              :uri "whatever"
                              :session {}})]
    (is (= (:status response) 302))
    (is (get-in response [:headers "Location"]))))

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

