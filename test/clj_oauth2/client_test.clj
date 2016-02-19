(ns clj-oauth2.client-test
  (:require [clj-oauth2.client :as client]
            [uri.core :as uri]
            [clojure.test :refer :all]
            [clj-oauth2.stub :as stub])
  (:import [clj_oauth2 OAuth2Exception OAuth2StateMismatchException]))

(use-fixtures :once stub/server)

(deftest grant-type-auth-code
  (let [req (client/make-auth-request stub/endpoint-auth-code "bazqux")
        uri (uri/uri->map (uri/make (:uri req)) true)]
    (testing "constructs a uri for the authorization redirect"
      (is (= (:scheme uri) "http"))
      (is (= (:host uri) stub/host))
      (is (= (:port uri) stub/port))
      (is (= (:path uri) "/auth"))
      (is (= (:query uri) {:response_type "code"
                           :client_id "foo"
                           :redirect_uri "http://my.host/cb"
                           :scope "foo bar"
                           :state "bazqux"})))
    (testing "contains the passed in scope and state"
      (is (= (:scope req) ["foo" "bar"]))
      (is (= (:state req) "bazqux"))))

  (testing "returns an access token hash-map on success"
    (is (= (:access-token (client/get-access-token
                           stub/endpoint-auth-code
                           {:code "abracadabra" :state "foo"}
                           {:state "foo"}))
           "sesame")))
  (testing "also works with client credentials passed in the authorization header"
    (is (= (:access-token (client/get-access-token (assoc stub/endpoint-auth-code
                                                          :authorization-header? true)
                                                   {:code "abracadabra" :state "foo"}
                                                   {:state "foo"}))
           "sesame")))
  (testing "also works with application/x-www-form-urlencoded responses (as produced by Facebook)"
    (is (= (:access-token (client/get-access-token (assoc stub/endpoint-auth-code :access-token-uri
                                                          (str (:access-token-uri stub/endpoint-auth-code)
                                                               "?formurlenc"))
                                                   {:code "abracadabra" :state "foo"}
                                                   {:state "foo"}))
           "sesame")))
  (testing "returns an access token when no state is given"
    (is (= (:access-token (client/get-access-token stub/endpoint-auth-code {:code "abracadabra"}))
           "sesame")))
  (testing "fails when state differs from expected state"
    (is (thrown? OAuth2StateMismatchException
                 (client/get-access-token stub/endpoint-auth-code
                                          {:code "abracadabra" :state "foo"}
                                          {:state "bar"}))))
  (testing "fails when an error response is passed in"
    (is (thrown? OAuth2Exception
                 (client/get-access-token stub/endpoint-auth-code
                                          {:error "invalid_client"
                                           :error_description "something went wrong"}))))
  (testing "raises on error response"
    (is (thrown? OAuth2Exception
                 (client/get-access-token (assoc stub/endpoint-auth-code
                                                 :access-token-uri
                                                 (str stub/server-uri "/token-error"))
                                          {:code "abracadabra" :state "foo"}
                                          {:state "foo"})))))

(deftest grant-type-resource-owner
  (testing "returns an access token hash-map on success"
    (is (= (:access-token (client/get-access-token stub/endpoint-resource-owner stub/resource-owner-credentials))
           "sesame")))
  (testing "fails when invalid credentials are given"
    (is (thrown? OAuth2Exception
                 (client/get-access-token
                   stub/endpoint-resource-owner
                   {:username "foo" :password "qux"})))))

(deftest token-usage
  (testing "should grant access to protected resources"
    (is (= "that's gold jerry!"
           (:body (client/request {:method :get
                                   :oauth2 stub/access-token
                                   :url (str stub/server-uri "/some-resource")})))))

  (testing "should preserve the url's query string when adding the access-token"
    (is (= {:foo "123" (:query-param stub/access-token) (:access-token stub/access-token)}
           (uri/form-url-decode
             (:body (client/request {:method :get
                                     :oauth2 stub/access-token
                                     :query-params {:foo "123"}
                                     :url (str stub/server-uri "/query-echo")}))))))

  (testing "should support passing bearer tokens through the authorization header"
    (is (= {:foo "123" :access_token (:access-token stub/access-token)}
           (uri/form-url-decode
             (:body (client/request {:method :get
                                     :oauth2 (dissoc stub/access-token :query-param)
                                     :query-params {:foo "123"}
                                     :url (str stub/server-uri "/query-and-token-echo")}))))))

  (testing "should deny access to protected resource given an invalid access token"
    (is (= "nope"
           (:body (client/request {:method :get
                                   :oauth2 (assoc stub/access-token :access-token "nope")
                                   :url (str stub/server-uri "/some-resource")
                                   :throw-exceptions false})))))

  (testing "pre-defined shortcut request functions"
    (let [req {:oauth2 stub/access-token}]
      (is (= "get" (:body (client/get (str stub/server-uri "/get") req))))
      (is (= "post" (:body (client/post (str stub/server-uri "/post") req))))
      (is (= "put" (:body (client/put (str stub/server-uri "/put") req))))
      (is (= "delete" (:body (client/delete (str stub/server-uri "/delete") req))))
      (is (= 200 (:status (client/head (str stub/server-uri "/head") req)))))))
