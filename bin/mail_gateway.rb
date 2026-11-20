#!/usr/bin/env ruby
# frozen_string_literal: true

# 邮件网关接入示例：从原始 RFC822 邮件提取字段 -> 检测 -> 决定是否投递。
# 生产环境建议替换为 mail gem 做完整 MIME/编码解析，本文件演示字段映射方式。
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "bec_detector"

module RawMailParser
  module_function

  def parse(raw)
    header_part = raw.split(/\r?\n\r?\n/, 2).first.to_s
    headers = {}
    header_part.split(/\r?\n/).each do |line|
      if line =~ /\A([A-Za-z0-9-]+):\s*(.*)\z/
        headers[Regexp.last_match(1).downcase] = Regexp.last_match(2)
      end
    end

    from_addr, display = parse_from(headers["from"].to_s)
    auth = ->(name) { (headers[name].to_s =~ /\Apass\b/i ? :pass : (headers[name].to_s.empty? ? :none : :fail)) }

    BecDetector::Email.new(
      id: headers["message-id"] || "raw-#{from_addr}",
      from_address: from_addr,
      display_name: display,
      reply_to: parse_addr(headers["reply-to"].to_s),
      subject: headers["subject"].to_s,
      body: raw.split(/\r?\n\r?\n/, 2).last.to_s,
      spf: auth.call("received-spf"),
      dkim: auth.call("dkim-signature") ? :pass : (headers.key?("dkim-signature") ? :pass : :none),
      dmarc: auth.call("x-dmarc-result"),
      has_link: raw.include?("http://") || raw.include?("https://"),
      has_attachment: headers["content-type"].to_s.include?("multipart/") || raw.include?("Content-Disposition: attachment")
    )
  end

  def parse_from(field)
    if field =~ /"?([^"<]+)"?\s*<([^>]+)>/
      [Regexp.last_match(2).strip, Regexp.last_match(1).strip]
    else
      [field.strip, nil]
    end
  end

  def parse_addr(field)
    field =~ /<([^>]+)>/ ? Regexp.last_match(1) : field.empty? ? nil : field.strip
  end
end

# 演示：一封题面式仿冒邮件
raw_mail = <<~MAIL
  From: "张明远 CEO" <ceo.zhang@beichen-teoh.com>
  Subject: 紧急：并购定金支付
  Message-ID: <msg-7781>
  Received-SPF: fail
  X-DMARC-Result: fail
  Content-Type: text/plain

  紧急：并购项目需要立即支付一笔定金，请今天下班前安排汇款，注意保密，账号见附件。
MAIL

email = RawMailParser.parse(raw_mail)
verdict = BecDetector::Detector.new(BecDetector::IdentityGraph.build_default).inspect(email)

puts "网关判定: #{verdict.action.upcase}（#{verdict.score}分）"
puts "处置动作: #{case verdict.action
                 when :block then "拒绝投递，退回发件服务器并告警安全团队"
                 when :quarantine then "扣留邮件，推入人工复核队列"
                 else "正常投递到员工收件箱"
                 end}"
puts "判定依据:"
verdict.top_reasons(3).each { |r| puts "  - #{r}" }
