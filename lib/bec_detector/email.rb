# frozen_string_literal: true

module BecDetector
  # 一封待检测邮件的结构化表示。
  # 生产环境由原始 RFC822 邮件解析得到（解析器见 bin/mail_gateway.rb 的简化示例），
  # 这里用结构化对象以便批量评测。
  class Email
    ATTRS = %i[
      id from_address display_name to_list cc_list subject body
      spf dkim dmarc reply_to in_reply_to thread_id
      has_attachment has_link sent_at
      label scenario_id scenario_name
    ].freeze

    attr_accessor(*ATTRS)

    def initialize(attrs = {})
      ATTRS.each do |k|
        send("#{k}=", attrs[k]) if attrs.key?(k)
      end
      @to_list ||= []
      @cc_list ||= []
      @spf   = :pass  unless attrs.key?(:spf)
      @dkim  = :pass  unless attrs.key?(:dkim)
      @dmarc = :pass  unless attrs.key?(:dmarc)
      @has_attachment ||= false
      @has_link       ||= false
    end

    # 发件人显示名（去掉装饰后的纯名字部分），如 "张伟 CEO" -> "张伟"
    def normalized_display_name
      return nil if display_name.nil? || display_name.to_s.strip.empty?
      display_name.gsub(/[（(].*?[)）]/, "")
                  .gsub(/\b(CEO|CFO|CTO|COO|VP|总经理|财务总监|董事长|总裁|经理|总监)\b/i, "")
                  .strip
    end

    def from_local
      from_address.to_s.split("@", 2).first.to_s.downcase
    end

    def from_domain
      from_address.to_s.split("@", 2).last.to_s.downcase
    end

    # 实际发件认证是否完全通过（被盗邮箱场景三项通常都是 pass）
    def auth_all_pass?
      spf == :pass && dkim == :pass && dmarc == :pass
    end

    def auth_failures
      %i[spf dkim dmarc].select { |m| send(m) != :pass }
    end

    def internal_thread?
      !thread_id.nil?
    end

    def reply?
      !in_reply_to.nil?
    end
  end
end
