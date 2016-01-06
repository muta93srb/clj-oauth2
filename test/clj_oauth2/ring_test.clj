(ns clj_oauth2.ring-test
  (:require [clojure.test :refer :all]
            [clj-oauth2.ring :as r]))

;; Stubbed out response that makes it possible verify that a handler was invoked by the wrapper
(def ok-response {:status 200
                  :body "ok"
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
        wrapper-fn (r/wrap-oauth2 (fn [req] {:will-not-be "invoked"})
                                  oauth2-config)
        response (wrapper-fn {:scheme "https"
                           :uri "whatever"
                           ;; No oauth ...
                           :session {}})]
    (is (= (:status response) 302))
    (is (get-in response [:headers "Location"]))))