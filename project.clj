(defproject bstd/clj-oauth2 "0.5.6"
  :description "clj-http and ring middlewares for OAuth 2.0"
  :url "https://github.com/13o6/clj-oauth2"
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [cheshire "5.5.0"]
                 [clj-http "1.1.0"]
                 [uri "1.1.0"]
                 [commons-codec/commons-codec "1.6"]
                 [ring "1.4.0"]]
  :aot [clj-oauth2.OAuth2Exception
        clj-oauth2.OAuth2StateMismatchException])
