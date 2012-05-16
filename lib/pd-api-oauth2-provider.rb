require 'oauth'
require 'oauth/signature/hmac/sha1'
require 'oauth/server'
require 'oauth/controllers/application_controller_methods'
require 'oauth/request_proxy/rack_request'

if Rails.version =~ /^3\./
  module OAuth
    module Plugin
      class OAuthRailtie < Rails::Railtie
        initializer "oauth-plugin.configure_rails_initialization" do |app|
          ActionController::Base.send :include, OAuth::Controllers::ApplicationControllerMethods
        end
      end
    end
  end
end
