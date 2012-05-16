require 'oauth/provider/authorizer'
module OAuth
  module Controllers

    module ProviderController
      def self.included(controller)
        controller.class_eval do
          before_filter :oauth_required, :only => [:test_request, :capabilities]
          before_filter :login_required, :only => [:revoke, :invalidate]

          # skip_before_filter :verify_authenticity_token, :only=>[:invalidate, :test_request, :token]
        end
      end

      def token
        @client_application = ClientApplication.find_by_key(params[:client_id])
        if @client_application.nil? || (@client_application.secret != params[:client_secret])
          oauth2_error "invalid_client"
          return
        end
        # older drafts used none for client_credentials
        params[:grant_type] = 'client_credentials' if params[:grant_type] == 'none'
        if ["authorization_code", "password", "client_credentials"].include?(params[:grant_type])
          send "oauth2_token_#{params[:grant_type].underscore}"
        else
          oauth2_error "unsupported_grant_type"
        end
      end

      def authorize
        if request.post?
          redirect_to OAuth::Provider::Authorizer.new(params).redirect_uri
        else
          @client_application = ClientApplication.find_by_key(params[:client_id])
        end
      end

      def test_request
        render :text => params.collect{|k,v|"#{k}=#{v}"}.join("&")
      end

      def revoke
        @token = current_user.tokens.find_by_token(params[:token])
        if @token
          @token.invalidate!
          flash[:notice] = "You've revoked the token for #{@token.client_application.name}"
        end
        redirect_to oauth_clients_url
      end

      # Invalidate current token
      def invalidate
        current_token.invalidate!
        head :status=>410
      end

      # Capabilities of current_token
      def capabilities
        if current_token.respond_to?(:capabilities)
          @capabilities=current_token.capabilities
        else
          @capabilities={:invalidate=>url_for(:action=>:invalidate)}
        end

        respond_to do |format|
          format.json {render :json=>@capabilities}
          format.xml {render :xml=>@capabilities}
        end
      end

      protected

      # http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-4.1.1
      def oauth2_token_authorization_code
        @verification_code =  @client_application.oauth2_verifiers.find_by_token(params[:code])
        unless @verification_code
          oauth2_error
          return
        end
        if @verification_code.redirect_url != params[:redirect_uri]
          oauth2_error
          return
        end
        @token = @verification_code.exchange!
        render :json => @token
      end

      # http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-4.1.2
      def oauth2_token_password
        @user = User.authenticate(params[:username], params[:password], params[:fb_token], @client_application.partner_id)
        unless @user
          oauth2_error('invalid username or password')
          return
        end
        @token = Oauth2Token.create(:client_application => @client_application, :user => @user, :scope => params[:scope])
        render :json => @token
      end

      # autonomous authorization which creates a token for client_applications user
      def oauth2_token_client_credentials
        @token = Oauth2Token.create(:client_application => @client_application, :scope=>params[:scope])
        render :json => @token
      end

      def oauth2_error(error = "invalid_grant" )
        render :json=> { :error=>error }.to_json
      end

    end
  end
end
