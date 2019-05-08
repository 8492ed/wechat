require 'wechat/http_client'

module Wechat
  module ControllerApi
    extend ActiveSupport::Concern

    module ClassMethods
      attr_accessor :wechat_api_client, :wechat_cfg_account, :token, :appid, :corpid, :agentid, :encrypt_mode, :timeout,
                    :skip_verify_ssl, :encoding_aes_key, :trusted_domain_fullname, :oauth2_cookie_duration
    end

    def wechat(account = nil)
      # Make sure user can continue access wechat at instance level similar to class level
      self.class.wechat(account)
    end

    def custom_wechat_oauth2(scope = 'snsapi_base', page_url = nil, account = nil, &block)
      puts "inside custom_wechat_oauth2".yellow
      # ensure wechat initialization
      self.class.corpid || self.class.appid || self.class.wechat

      api = wechat(account)
      if account
        config = Wechat.config(account)
        appid = config.corpid || config.appid
        is_crop_account = !!config.corpid
      else
        appid = self.class.corpid || self.class.appid
        is_crop_account = !!self.class.corpid
      end

      raise 'Can not get corpid or appid, so please configure it first to using wechat_oauth2' if appid.blank?

      oauth2_params = {
        appid: appid,
        redirect_uri: page_url || generate_redirect_uri(account),
        scope: scope,
        response_type: 'code',
        state: api.jsapi_ticket.oauth2_state
      }

      puts "inside wechat_public_oauth2".yellow
      openid  = cookies.signed_or_encrypted[:we_openid]
      unionid = cookies.signed_or_encrypted[:we_unionid]
      we_token = cookies.signed_or_encrypted[:we_access_token]

      puts "here 3".yellow
      puts "oauth params #{oauth2_params}".yellow
      puts "url #{generate_oauth2_url(oauth2_params)}".yellow
      redirect_to generate_oauth2_url(oauth2_params)
    end

    def wechat_oauth2(scope = 'snsapi_base', page_url = nil, account = nil, &block)
      # ensure wechat initialization
      self.class.corpid || self.class.appid || self.class.wechat

      api = wechat(account)
      if account
        config = Wechat.config(account)
        appid = config.corpid || config.appid
        is_crop_account = !!config.corpid
      else
        appid = self.class.corpid || self.class.appid
        is_crop_account = !!self.class.corpid
      end

      raise 'Can not get corpid or appid, so please configure it first to using wechat_oauth2' if appid.blank?

      oauth2_params = {
        appid: appid,
        redirect_uri: page_url || generate_redirect_uri(account),
        scope: scope,
        response_type: 'code',
        state: api.jsapi_ticket.oauth2_state
      }

      return generate_oauth2_url(oauth2_params) unless block_given?
      is_crop_account ? wechat_corp_oauth2(oauth2_params, account, &block) : wechat_public_oauth2(oauth2_params, account, &block)
    end

    def wechat_user_info(account = nil, code)
      puts "wechat_user_info #{account},#{code}".yellow
      api = wechat(account)
      if account
        config = Wechat.config(account)
        appid = config.corpid || config.appid
        secret = config.secret
      else
        appid = self.class.corpid || self.class.appid
        is_crop_account = !!self.class.corpid
      end
      raise 'Can not get corpid or appid, so please configure it first to using wechat_oauth2' if appid.blank?

      results =  get_oauth2_access_token(code,appid,secret)
      puts "results 1 #{results}".red
      puts "access_token #{results["access_token"]}".red
      puts "openid #{results["openid"]}".red
      client = HttpClient.new('https://api.weixin.qq.com/sns/', 20, true)
      results = client.get "userinfo?access_token=#{results["access_token"]}&openid=#{results["openid"]}&lang=zh_CN"
      puts "results #{results}".red 
      return results
    end

    private

    def get_oauth2_access_token(code,appid,secret)
      puts "get_oauth2_access_token #{code},#{appid},#{secret} ".yellow
      client = HttpClient.new('https://api.weixin.qq.com/sns/', 20, true)
      client.get "oauth2/access_token?appid=#{appid}&secret=#{secret}&code=#{code}&grant_type=authorization_code"
    end

    def wechat_public_oauth2(oauth2_params, account = nil)
      openid  = cookies.signed_or_encrypted[:we_openid]
      unionid = cookies.signed_or_encrypted[:we_unionid]
      we_token = cookies.signed_or_encrypted[:we_access_token]
      if openid.present?
        yield openid, { 'openid' => openid, 'unionid' => unionid, 'access_token' => we_token}
      elsif params[:code].present? && params[:state] == oauth2_params[:state]
        access_info = wechat(account).web_access_token(params[:code])
        cookies.signed_or_encrypted[:we_openid] = { value: access_info['openid'], expires: self.class.oauth2_cookie_duration.from_now }
        cookies.signed_or_encrypted[:we_unionid] = { value: access_info['unionid'], expires: self.class.oauth2_cookie_duration.from_now }
        cookies.signed_or_encrypted[:we_access_token] = { value: access_info['access_token'], expires: self.class.oauth2_cookie_duration.from_now }
        yield access_info['openid'], access_info
      else
        redirect_to generate_oauth2_url(oauth2_params)
      end
    end

    def wechat_corp_oauth2(oauth2_params, account = nil)
      userid   = cookies.signed_or_encrypted[:we_userid]
      deviceid = cookies.signed_or_encrypted[:we_deviceid]
      if userid.present? && deviceid.present?
        yield userid, { 'UserId' => userid, 'DeviceId' => deviceid }
      elsif params[:code].present? && params[:state] == oauth2_params[:state]
        userinfo = wechat(account).getuserinfo(params[:code])
        cookies.signed_or_encrypted[:we_userid] = { value: userinfo['UserId'], expires: self.class.oauth2_cookie_duration.from_now }
        cookies.signed_or_encrypted[:we_deviceid] = { value: userinfo['DeviceId'], expires: self.class.oauth2_cookie_duration.from_now }
        yield userinfo['UserId'], userinfo
      else
        redirect_to generate_oauth2_url(oauth2_params)
      end
    end

    def generate_redirect_uri(account = nil)
      domain_name = if account
        Wechat.config(account).trusted_domain_fullname
      else
        self.class.trusted_domain_fullname
      end
      page_url = domain_name ? "#{domain_name}#{request.original_fullpath}" : request.original_url
      safe_query = request.query_parameters.reject { |k, _| %w(code state access_token).include? k }.to_query
      page_url.sub(request.query_string, safe_query)
    end

    def generate_oauth2_url(oauth2_params)
      if oauth2_params[:scope] == 'snsapi_login'
        "https://open.weixin.qq.com/connect/qrconnect?#{oauth2_params.to_query}#wechat_redirect"
      else
        "https://open.weixin.qq.com/connect/oauth2/authorize?#{oauth2_params.to_query}#wechat_redirect"
      end
    end
  end
end
