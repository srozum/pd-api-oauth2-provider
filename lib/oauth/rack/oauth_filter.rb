require "rack"
require "rack/request"
require "oauth"
require "oauth/request_proxy/rack_request"

module OAuth
  module Rack

    # Add it as middleware to your config/application.rb:
    #
    # require 'oauth/rack/oauth_filter'
    # config.middleware.use OAuth::Rack::OAuthFilter

    class OAuthFilter
      def initialize(app)
        @app = app
      end

      def call(env)
        request = ::Rack::Request.new(env)
        env["oauth_plugin"] = true
        if token_string = oauth2_token(request)
          if token = Oauth2Token.first(:conditions => ['invalidated_at IS NULL AND authorized_at IS NOT NULL and token = ?', token_string])
            env["oauth.token"]   = token
          end
        end
        @app.call(env)
      end

      def oauth2_token(request)
        request.params['bearer_token'] || request.params['access_token'] || (request.params["oauth_token"] && !request.params["oauth_signature"] ? request.params["oauth_token"] : nil )  ||
          request.env["HTTP_AUTHORIZATION"] &&
          !request.env["HTTP_AUTHORIZATION"][/(oauth_version="1.0")/] &&
          request.env["HTTP_AUTHORIZATION"][/^(Bearer|OAuth|Token) ([^\s]*)$/, 2]
      end
    end
  end
end