require "rexml/document"
require 'digest'

module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    # For more information on GlobalOne, visit the {developer portal}[https://developer.pivotalpayments.com/globalone]
    # https://testpayments.globalone.me/merchant/gateway.xsd
    # Currency  Terminal ID  Shared SECRET
    # USD       33001        SandboxSecret001
    # CAD       33002        SandboxSecret002
    # EUR       33003        SandboxSecret003
    # GBP       33004        SandboxSecret004
    # MCP       36001        SandboxSecret001

    class GlobalOneGateway < Gateway
      API_VERSION = "6.4"

      POST_HEADERS = {
        "Content-Type" => "application/xml",
        "Accept" => "application/xml"

      }

      GLOBAL_ONE_DATE_FORMAT= "%d-%m-%Y:%T:%L"

      SUCCESS = '0'
      APPROVED = "A"

      ECOMMERCE_TERMINAL_TYPE = 1
      ECOMMERCE_TRANSACTION_TYPE = 7

      RESPONSE_CODES = [
        "101", #Terminal not found.
        "102", #BIN not found.
        "103", #Currencies are the same.
        "104", # eDCC is not allowed for the terminal.
        "105", # Invalid card currency/Unknown currency.
        "106", #Conversion rate not found.
        "107", #Invalid request format.
        "108", #Invalid hash in the request.
        "109", #Other error.
        "110", #Internal error.
        "111" #Unsupported card currency.
      ]

      ERROR_CODES = [
        "E01", # SYSTEM ERROR – TRY AGAIN
        "E03", # OPERATION NOT ALLOWED
        "E04", # INVALID REFERENCE DETAILS
        "E05", # INVALID CARD TYPE
        "E06", # INVALID TERMINALID
        "E07", # METHOD NOT SUPPORTED
        "E08", # INVALID MERCHANTREF
        "E09", # INVALID DATETIME
        "E10", # INVALID CARDNUMBER
        "E11", # INVALID CARDEXPIRY
        "E12", # INVALID CARDHOLDERNAME
        "E13" # INVALID HASH
      ]

      self.test_url = "https://testpayments.globalone.me/merchant/xmlpayment"
      self.live_url = "https://payments.globalone.me/merchant/xmlpayment"

      self.supported_countries = ["US", "CA"]
      self.default_currency = "CAD"
      self.supported_cardtypes = [:visa, :master, :american_express, :discover, :diners_club, :jcb]

      self.display_name = 'Global One'
      self.homepage_url = 'http://www.globalonepay.com'

      self.money_format = :dollars

      AVS_SUPPORTED_COUNTRIES = ['US', 'CA', 'UK', 'GB']

      CURRENCY_CODES = {
        "AUD" => '036',
        "CAD" => '124',
        "CZK" => '203',
        "DKK" => '208',
        "HKD" => '344',
        "ICK" => '352',
        "JPY" => '392',
        "MXN" => '484',
        "NZD" => '554',
        "NOK" => '578',
        "SGD" => '702',
        "SEK" => '752',
        "CHF" => '756',
        "GBP" => '826',
        "USD" => '840',
        "EUR" => '978'
      }

      CURRENCY_EXPONENTS = {
        "AUD" => '2',
        "CAD" => '2',
        "CZK" => '2',
        "DKK" => '2',
        "HKD" => '2',
        "ICK" => '2',
        "JPY" => '0',
        "MXN" => '2',
        "NZD" => '2',
        "NOK" => '2',
        "SGD" => '2',
        "SEK" => '2',
        "CHF" => '2',
        "GBP" => '2',
        "USD" => '2',
        "EUR" => '2'
      }

      # Auth
      PREAUTH = 'PREAUTH'
      # Capture
      PREAUTHCOMPLETION = 'PREAUTHCOMPLETION'
      # AC - Auth and Capture = 'AC'
      PAYMENT = 'PAYMENT'
      # Refund and Capture
      REFUND = 'REFUND'

      # STORAGE
      SECURECARDREGISTRATION = "SECURECARDREGISTRATION"
      SECURECARDUPDATE = "SECURECARDUPDATE"
      SECURECARDREMOVAL = "SECURECARDREMOVAL"
      SECURECARDSEARCH = "SECURECARDSEARCH"

      SECURECARD = "SECURECARD"

      REFUND_OPERATOR = "System Operator"
      REFUND_REASON = "Return of goods"

      SENSITIVE_FIELDS = [:account_num]

      def initialize(options = {})
        requires!(options, :terminal_id)
        requires!(options, :shared_secret)
        super
      end

      # A – Authorization request
      # card_reference can be used instead of a credit card number.
      def authorize(money, creditcard, options = {})
        options[:order_id] ||= Time.now.to_i
        options[:order_datetime] ||= DateTime.now
        order = build_new_order_xml(PREAUTH, money, creditcard, options) do |xml|
          #TERMINALID+ORDERID+AMOUNT+DATETIME+secret
          #TERMINALID+ORDERID+CURRENCY+AMOUNT+DATETIME+secret
          hash_string =
              "#{self.options[:terminal_id]}" +
              "#{options[:order_id]}" +
              "#{amount(money)}" +
              "#{format_date_field(options[:order_datetime])}" +
              "#{self.options[:shared_secret]}"
          hash = Digest::MD5.hexdigest(hash_string)
          if options[:card_reference]
            add_securecard_profile(xml, options[:card_reference], options[:currency], hash)
          else
            add_creditcard(xml, creditcard, options[:currency], hash)
          end
          add_address(xml, options[:address]) if options[:address]
        end
        commit(order, :authorize)
      end

      def verify(creditcard, options = {})
        MultiResponse.run(:use_first_response) do |r|
          r.process { authorize(100, creditcard, options) }
          r.process(:ignore_result) { void(r.authorization) }
        end
      end

      # AC – Authorization and Capture
      # A – Authorization request
      # card_reference can be used instead of a credit card number.
      def purchase(money, creditcard, options = {})
        options[:order_id] ||= Time.now.to_i
        options[:order_datetime] ||= DateTime.now
        order = build_new_order_xml(PAYMENT, money, creditcard, options) do |xml|
          #TERMINALID+ORDERID+AMOUNT+DATETIME+secret
          #TERMINALID+ORDERID+CURRENCY+AMOUNT+DATETIME+secret
          hash_string =
              "#{self.options[:terminal_id]}" +
              "#{options[:order_id]}" +
              "#{amount(money)}" +
              "#{format_date_field(options[:order_datetime])}" +
              "#{self.options[:shared_secret]}"
          hash = Digest::MD5.hexdigest(hash_string)
          if options[:card_reference]
            add_securecard_profile(xml, options[:card_reference], options[:currency], hash)
          else
            add_creditcard(xml, creditcard, options[:currency], hash)
          end
          add_address(xml, options[:address]) if options[:address]
        end
        commit(order, :authorize)
      end


      # MFC - Mark For Capture
      def capture(money, authorization, options = {})
        options[:order_datetime] ||= DateTime.now
        order = build_new_order_xml(PREAUTHCOMPLETION, money, nil, options.merge(:authorization => authorization)) do |xml|
          hash_string =
              "#{self.options[:terminal_id]}" +
              "#{authorization.authorization}" +
              "#{amount(money)}" +
              "#{format_date_field(options[:order_datetime])}" +
              "#{self.options[:shared_secret]}"
          hash = Digest::MD5.hexdigest(hash_string)
          add_hash(xml, hash)
        end
        commit(order, :capture)
      end

      # R – Refund request
      def refund(money, authorization, options = {})
        options[:order_datetime] ||= DateTime.now
        order = build_new_order_xml(REFUND, money, nil, options.merge(:authorization => authorization)) do |xml|
          hash_string =
              "#{self.options[:terminal_id]}" +
              "#{authorization.authorization}" +
              "#{amount(money)}" +
              "#{format_date_field(options[:order_datetime])}" +
              "#{self.options[:shared_secret]}"
          hash = Digest::MD5.hexdigest(hash_string)
          add_refund(xml, hash)
        end
        commit(order, :refund)
      end

      def void(authorization, options = {}, deprecated = {})
        if(!options.kind_of?(Hash))
          ActiveMerchant.deprecated("Calling the void method with an amount parameter is deprecated and will be removed in a future version.")
          return void(options, deprecated.merge(:amount => authorization))
        end

        order = build_void_request_xml(authorization, options)
        commit(order, :void)
      end


      # ==== Customer Profiles
      # :customer_ref_num should be set unless you're happy with Orbital providing one
      #
      # :customer_profile_order_override_ind can be set to map
      # the CustomerRefNum to OrderID or Comments. Defaults to 'NO' - no mapping
      #
      #   'NO' - No mapping to order data
      #   'OI' - Use <CustomerRefNum> for <OrderID>
      #   'OD' - Use <CustomerRefNum> for <Comments>
      #   'OA' - Use <CustomerRefNum> for <OrderID> and <Comments>
      #
      # :order_default_description can be set optionally. 64 char max.
      #
      # :order_default_amount can be set optionally. integer as cents.
      #
      # :status defaults to Active
      #
      #   'A' - Active
      #   'I' - Inactive
      #   'MS'  - Manual Suspend

      def add_customer_profile(creditcard, options = {})
        options[:merchant_ref] ||= SecureRandom.hex
        options[:order_datetime] ||= DateTime.now
        order = build_customer_request_xml(SECURECARDREGISTRATION, options[:merchant_ref], creditcard, options) do |xml|
          #TERMINALID+MERCHANTREF+DATETIME+CARDNUMBER+CARDEXPIRY+CARDTYPE+CARDHOLDERNAME+ SECRET
          hash_string =
              "#{self.options[:terminal_id]}" +
              "#{options[:merchant_ref]}" +
              "#{format_date_field(options[:order_datetime])}" +
              "#{creditcard.number}" +
              "#{expiry_date(creditcard)}" +
              "#{card_type(creditcard.brand)}" +
              "#{creditcard.name}" +
              "#{self.options[:shared_secret]}"
          hash = Digest::MD5.hexdigest(hash_string)
          add_profile_creditcard(xml, creditcard, hash)
        end
        commit(order, :authorize)
      end

      def update_customer_profile(creditcard, options = {})
        requires!(options, :merchant_ref)
        options[:order_datetime] ||= DateTime.now
        order = build_customer_request_xml(SECURECARDUPDATE, options[:merchant_ref], creditcard, options) do |xml|
          #TERMINALID+MERCHANTREF+DATETIME+CARDNUMBER+CARDEXPIRY+CARDTYPE+CARDHOLDERNAME+ SECRET
          hash_string =
              "#{self.options[:terminal_id]}" +
              "#{options[:merchant_ref]}" +
              "#{format_date_field(options[:order_datetime])}" +
              "#{creditcard.number}" +
              "#{expiry_date(creditcard)}" +
              "#{card_type(creditcard.brand)}" +
              "#{creditcard.name}" +
              "#{self.options[:shared_secret]}"
          hash = Digest::MD5.hexdigest(hash_string)
          add_profile_creditcard(xml, creditcard, hash)
        end
        commit(order, :authorize)
      end

      def delete_customer_profile(options ={})
        requires!(options, :merchant_ref)
        requires!(options, :card_reference)
        options[:order_datetime] ||= DateTime.now
        order = build_customer_request_xml(SECURECARDREMOVAL, options[:merchant_ref], nil, options) do |xml|
          #TERMINALID+MERCHANTREF+DATETIME+CARDREFERENCE+SECRET
          hash_string =
              "#{self.options[:terminal_id]}" +
              "#{options[:merchant_ref]}" +
              "#{format_date_field(options[:order_datetime])}" +
              "#{options[:card_reference]}" +
              "#{self.options[:shared_secret]}"
          hash = Digest::MD5.hexdigest(hash_string)
          add_hash(xml, hash)
        end
        commit(order, :authorize)
      end

      private

      def add_customer_data(xml, creditcard, options)
        if options[:profile_txn]
          xml.tag! :CustomerRefNum, options[:customer_ref_num]
        else
          if options[:customer_ref_num]
            if creditcard
              xml.tag! :CustomerProfileFromOrderInd, USE_CUSTOMER_REF_NUM
            end
            xml.tag! :CustomerRefNum, options[:customer_ref_num]
          else
            xml.tag! :CustomerProfileFromOrderInd, AUTO_GENERATE
          end
          xml.tag! :CustomerProfileOrderOverrideInd, options[:customer_profile_order_override_ind] || NO_MAPPING_TO_ORDER_DATA
        end
      end

      def add_address(xml, address)
        address = address || {}

        xml.tag! :ADDRESS1, address[:address1] if address[:address1]
        xml.tag! :ADDRESS2, address[:address2] if address[:address2]
        xml.tag! :POSTCODE, address[:zip] if address[:zip]
        xml.tag! :CITY, address[:city] if address[:city]
        xml.tag! :REGION, address[:state] if address[:state]
        xml.tag! :COUNTRY, address[:country] if address[:country]
      end

      def add_creditcard(xml, creditcard, currency=nil, hash="", cvv=true)
        unless creditcard.nil?
          xml.tag! :CARDNUMBER, creditcard.number
          xml.tag! :CARDTYPE, card_type(creditcard.brand)
          xml.tag! :CARDEXPIRY, expiry_date(creditcard)
          xml.tag! :CARDHOLDERNAME, creditcard.name
        end

        xml.tag! :HASH, hash
        xml.tag! :CURRENCY, (currency || self.default_currency)

        xml.tag! :TERMINALTYPE, ECOMMERCE_TERMINAL_TYPE
        xml.tag! :TRANSACTIONTYPE, ECOMMERCE_TRANSACTION_TYPE

        unless creditcard.nil?
          xml.tag! :CVV,  creditcard.verification_value if creditcard.verification_value? && cvv
        end
      end

      def add_profile_creditcard(xml, creditcard, hash="")
        unless creditcard.nil?
          xml.tag! :CARDNUMBER, creditcard.number
          xml.tag! :CARDEXPIRY, expiry_date(creditcard)
          xml.tag! :CARDTYPE, card_type(creditcard.brand)
          xml.tag! :CARDHOLDERNAME, creditcard.name
        end

        xml.tag! :HASH, hash

        unless creditcard.nil?
          xml.tag! :CVV,  creditcard.verification_value if creditcard.verification_value?
        end
      end

      def add_securecard_profile(xml, card_reference, currency=nil, hash="")
        unless card_reference.nil?
          xml.tag! :CARDNUMBER, card_reference
          xml.tag! :CARDTYPE, SECURECARD
        end

        xml.tag! :HASH, hash
        xml.tag! :CURRENCY, (currency || self.default_currency)

        xml.tag! :TERMINALTYPE, ECOMMERCE_TERMINAL_TYPE
        xml.tag! :TRANSACTIONTYPE, ECOMMERCE_TRANSACTION_TYPE
      end

      def add_refund(xml, hash)
        xml.tag! :HASH, hash
        xml.tag! :OPERATOR, REFUND_OPERATOR
        xml.tag! :REASON, REFUND_REASON
      end

      def add_hash(xml, hash)
        xml.tag! :HASH, hash
      end

      def parse(body)
        response = {}
        xml = REXML::Document.new(body)
        root = xml.root
        if root
          root.elements.to_a.each do |node|
            recurring_parse_element(response, node)
          end
        end

        response.delete_if { |k,_| SENSITIVE_FIELDS.include?(k) }
      end

      def recurring_parse_element(response, node)
        if node.has_elements?
          node.elements.each{|e| recurring_parse_element(response, e) }
        else
          response[node.name.underscore.to_sym] = node.text
        end
      end

      def commit(order, message_type)
        headers = POST_HEADERS.merge("Content-length" => order.size.to_s)
        url = test? ? self.test_url : self.live_url

        raw = ssl_post(url, order, headers)
        response = parse(raw)

        # UNIQUEREF APPROVALCODE  RESPONSECODE RESPONSETEXT
        Response.new(success?(response, message_type), message_from(response), response,
          {
             :authorization => response[:uniqueref],
             :test => self.test?,
             :avs_result => { :code => response[:avsresponse] },
             :cvv_result => response[:cvvresponse]
          }
        )
      end

      def remote_url
        self.test? ? self.test_url : self.live_url
      end

      def card_type(brand)
        case
        when brand.start_with?("v")
          "VISA"
        when brand.start_with?("m")
          "MASTERCARD"
        when brand.start_with?("a")
          "AMEX"
        else
          "UNKNOWN"
        end
      end

      def success?(response, message_type)
        if [:refund, :void].include?(message_type)
          response[:responsecode] == APPROVED
        elsif response[:customer_profile_action]
          response[:responsecode] == APPROVED
        else
          response[:responsecode] == APPROVED
        end
      end

      def message_from(response)
        response[:responsetext] || response[:errorstring]
      end

      def build_new_order_xml(action, money, creditcard = nil, parameters = {})
        xml = xml_envelope
        xml.tag! action do
          if parameters[:authorization]
            xml.tag! :UNIQUEREF, parameters[:authorization].authorization
          else
            xml.tag! :ORDERID, format_order_id(parameters[:order_id])
          end
          xml.tag! :TERMINALID, self.options[:terminal_id]
          xml.tag! :AMOUNT, amount(money) if money
          xml.tag! :DATETIME, format_date_field(parameters[:order_datetime])

          yield xml if block_given?
        end
        xml.target!
      end

      def build_customer_request_xml(action, merchant_ref, creditcard = nil, parameters = {})
        xml = xml_envelope
        xml.tag! action do
          xml.tag! :MERCHANTREF, merchant_ref
          xml.tag! :CARDREFERENCE, parameters[:card_reference] if parameters[:card_reference]
          xml.tag! :TERMINALID, self.options[:terminal_id]
          xml.tag! :DATETIME, format_date_field(parameters[:order_datetime])

          yield xml if block_given?
        end
        xml.target!
      end

      def expiry_date(credit_card)
        "#{format(credit_card.month, :two_digits)}#{format(credit_card.year, :two_digits)}"
      end

      def xml_envelope
        xml = Builder::XmlMarkup.new(:indent => 2)
        xml.instruct!(:xml, :version => '1.0', :encoding => 'UTF-8')
        xml
      end

      # The valid characters include:
      #
      # 1. all letters and digits
      # 2. - , $ @ & and a space character, though the space character cannot be the leading character
      # 3. PINless Debit transactions can only use uppercase and lowercase alpha (A-Z, a-z) and numeric (0-9)
      def format_order_id(order_id)
        illegal_characters = /[^,$@&\- \w]/
        order_id = order_id.to_s.gsub(/\./, '-')
        order_id.gsub!(illegal_characters, '')
        order_id.lstrip!
        order_id[0...22]
      end

      # Address-related fields cannot contain % | ^ \ /
      # Returns the value with these characters removed, or nil
      def format_address_field(value)
        value.gsub(/[%\|\^\\\/]/, '') if value.respond_to?(:gsub)
      end

      def format_date_field(value)
        value.strftime(GLOBAL_ONE_DATE_FORMAT) if value.respond_to?(:strftime)
      end

      # Field lengths should be limited by byte count instead of character count
      # Returns the truncated value or nil
      def byte_limit(value, byte_length)
        limited_value = ""

        value.to_s.each_char do |c|
          break if((limited_value.bytesize + c.bytesize) > byte_length)
          limited_value << c
        end

        limited_value
      end
    end
  end
end
